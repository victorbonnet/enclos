//! A sandbox's policy through the engine: its versions, and `policy allow`
//! (design §7).

use super::*;
use crate::model::sandbox::SandboxName;

/// An initialized engine with sandbox `home`, created as the CLI does.
pub(super) fn with_sandbox() -> (TempDir, Engine, SandboxName) {
    with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt))
}

pub(super) fn with_sandbox_on(backend: FakeBackend) -> (TempDir, Engine, SandboxName) {
    with_sandbox_under(backend, &super::Root::usual())
}

/// [`with_sandbox_on`], enclos's folder at `root`.
pub(super) fn with_sandbox_under(
    backend: FakeBackend,
    root: &super::Root,
) -> (TempDir, Engine, SandboxName) {
    let (dir, engine) = engine_under(vec![Box::new(backend)], root);
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let name: SandboxName = "home".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    (dir, engine, name)
}

/// What a grant over the folder the user's manager reads units from would
/// be: a unit written there runs outside the sandbox at the next login.
#[cfg(target_os = "linux")]
#[test]
fn a_write_grant_that_holds_the_users_unit_folder_is_refused() {
    let (_dir, engine, name) = with_sandbox();
    let mut policy = engine.active_policy(&name).unwrap().1.policy;
    policy.fs.write.push("~/.config".into());
    let ctx = engine.validation_context(&name, BackendKind::Seatbelt);
    let err = crate::policy::validate::validate_writes(&policy, &ctx)
        .unwrap_err()
        .to_string();
    let units = engine.layout.units_dir().display().to_string();
    assert!(err.contains(&units), "{err}");
}

#[test]
fn a_new_sandbox_gets_version_1_of_its_template() {
    let (_dir, engine, name) = with_sandbox();
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1);
    assert_eq!(view.snapshot.inputs.template.as_str(), "assistant");
    assert_eq!(view.snapshot.policy.fs.write, ["{home}"]);
    assert!(view.file.exists());
    assert!(engine.layout.sandbox_home("home").is_dir());
}

#[test]
fn allow_adds_a_version_and_an_audit_entry() {
    let (_dir, engine, name) = with_sandbox();
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "API.Example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    assert_eq!(applied.version.version, 2);
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.snapshot.policy.net.allow, ["api.example.com"]);
    assert!(
        std::fs::read_to_string(&view.file)
            .unwrap()
            .contains("\"api.example.com\"")
    );

    // Allowing it again changes nothing.
    let again = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(!again.changed);
    assert_eq!(engine.state.policy_history(&name).unwrap().len(), 2);

    let entries = engine.audit(None).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.intent.command, "policy allow");
    assert_eq!(last.intent.target.as_deref(), Some("home api.example.com"));
}

#[test]
fn unsafe_destinations_are_refused_and_change_nothing() {
    let (_dir, engine, name) = with_sandbox();
    for bad in [
        "*.com",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.5",
    ] {
        let err = engine
            .policy_allow(&alice(), &name, bad, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::Policy(_)), "{bad}: {err}");
        assert_eq!(err.exit_code(), 2, "{bad}: {err}");
    }
    for malformed in ["exa mple.com", "example.com:0", "intranet"] {
        let err = engine
            .policy_allow(&alice(), &name, malformed, Confirm::Ask)
            .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{malformed}: {err}");
    }
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
}

#[test]
fn a_hand_edit_the_policy_refuses_exits_2_and_one_that_does_not_parse_exits_1() {
    let (_dir, engine, name) = with_sandbox();
    let file = engine.layout.policy_file("home");
    let original = std::fs::read_to_string(&file).unwrap();
    // Replacing the read-deny list drops what enclos always hides.
    let dropped = original.replace("read_deny_add = []", "read_deny = []");
    std::fs::write(&file, &dropped).unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
        .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    assert!(err.to_string().contains("read_deny_add instead"), "{err}");

    std::fs::write(&file, original + "[network\n").unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
        .unwrap_err();
    assert_eq!(err.exit_code(), 1, "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
}

#[test]
fn an_edit_that_drops_a_hidden_path_is_refused_without_restore_advice() {
    let (_dir, engine, name) = with_sandbox();
    let before = engine.layout.read_policy("home").unwrap();
    let after = before.replace("read_deny_add = []", "read_deny = []");
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    let said = err.to_string();
    assert!(said.contains("read_deny_add instead"), "{said}");
    // Restoring a version is the rollback's business, not an edit's.
    assert!(!said.contains("restore"), "{said}");
    assert!(!said.contains("make its change again"), "{said}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
}

#[test]
fn a_dry_run_changes_nothing() {
    let (_dir, engine, name) = with_sandbox();
    let planned = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
        .unwrap();
    assert!(
        matches!(planned, Planned::DryRun(ref plan) if plan.changes.len() == 1),
        "{planned:?}"
    );
    assert!(
        engine
            .policy(&name)
            .unwrap()
            .snapshot
            .policy
            .net
            .allow
            .is_empty()
    );
}

#[test]
fn allowing_an_entry_the_file_already_lists_applies_it() {
    let (_dir, engine, name) = with_sandbox();
    let file = engine.layout.policy_file("home");
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("allow_add = []", "allow_add = [\"new.example.com\"]");
    std::fs::write(&file, text).unwrap();
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "new.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 2);
    assert_eq!(view.snapshot.policy.net.allow, ["new.example.com"]);
}

/// Rewrites the sandbox's `policy.toml`, as a user editing it would.
fn edit_policy(engine: &Engine, from: &str, to: &str) {
    let file = engine.layout.policy_file("home");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains(from), "{text}");
    std::fs::write(&file, text.replace(from, to)).unwrap();
}

#[test]
fn allowing_with_other_edits_pending_asks_and_names_them() {
    let (dir, engine, name) = with_sandbox();
    std::fs::create_dir(dir.path().join("work")).unwrap();
    let work = dir.path().join("work").display().to_string();
    edit_policy(
        &engine,
        "write_add = []",
        &format!("write_add = [\"{work}\"]"),
    );

    let planned = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert_eq!(plan.changes.len(), 2, "{plan:?}");
    assert!(plan.changes[1].contains(&work), "{plan:?}");

    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(err.to_string().contains(&work), "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);

    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(applied.version.version, 2);
    assert_eq!(applied.also.len(), 1, "{:?}", applied.also);
    let summary = engine.audit(None).unwrap().pop().unwrap();
    assert!(format!("{summary:?}").contains(&work), "{summary:?}");
}

#[test]
fn a_dry_run_reports_what_the_real_run_would() {
    let (_dir, engine, name) = with_sandbox();
    done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    let planned = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::DryRun)
        .unwrap();
    assert!(
        matches!(&planned, Planned::DryRun(plan) if plan.changes[0].contains("change nothing")),
        "{planned:?}"
    );
    // A private address without its opt-in is refused by a dry run too.
    let err = engine
        .policy_allow(&alice(), &name, "192.168.1.5", Confirm::DryRun)
        .unwrap_err();
    assert!(matches!(err, Error::Policy(_)), "{err}");
}

#[test]
fn a_failed_file_write_adds_no_version_and_the_retry_applies() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, engine, name) = with_sandbox();
    let folder = engine
        .layout
        .policy_file("home")
        .parent()
        .unwrap()
        .to_owned();
    let mode = |m| std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(m));
    mode(0o500).unwrap();
    let failed = engine.policy_allow(&alice(), &name, "api.example.com", Confirm::Ask);
    mode(0o700).unwrap();
    assert!(failed.is_err(), "{failed:?}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);

    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    assert_eq!(applied.version.version, 2);
}

#[test]
fn a_hand_edit_that_grants_enclos_files_is_refused() {
    let (_dir, engine, name) = with_sandbox();
    let file = engine.layout.policy_file("home");
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("write_add = []", "write_add = [\"~\"]");
    std::fs::write(&file, text).unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
        .unwrap_err();
    assert!(err.to_string().contains("enclos's own files"), "{err}");
    assert_eq!(err.exit_code(), 2, "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
}

#[test]
fn unknown_sandboxes_are_named_in_the_error() {
    let (_dir, engine) = engine();
    done(engine.init(&alice(), Confirm::Yes).unwrap());
    let err = engine.policy(&"nope".parse().unwrap()).unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
}
