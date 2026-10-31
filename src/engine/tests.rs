use tempfile::TempDir;

use super::*;
use crate::backend::fake::FakeBackend;
use crate::error::{Error, HomeFound};
use crate::model::audit::AuditResult;

/// The shell `connect` runs when given no command, as a plan shows it.
fn default_shell() -> String {
    crate::backend::environment::shell_command()
        .iter()
        .map(|word| word.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

fn alice() -> Actor {
    Actor {
        user: "alice".into(),
        host: "mac".into(),
    }
}

fn engine_with(backends: Vec<Box<dyn Backend>>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("enclos"));
    let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
    let audit = JsonlAuditLog::new(layout.audit_log());
    let engine = Engine::new(layout, Box::new(state), Box::new(audit), backends);
    (dir, engine)
}

fn engine() -> (TempDir, Engine) {
    engine_with(Vec::new())
}

fn done<T>(planned: Planned<T>) -> T {
    match planned {
        Planned::Done(value) => value,
        Planned::DryRun(plan) => panic!("expected a change, got the plan {plan:?}"),
    }
}

#[test]
fn init_creates_the_layout_and_a_finished_audit_entry() {
    let (_dir, engine) = engine();
    let report = done(engine.init(&alice(), Confirm::Ask).unwrap());
    assert_eq!(report.created, engine.layout.paths());
    assert_eq!(report.migration.from, 0);
    assert!(engine.layout.missing().is_empty());

    let entries = engine.audit(None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].intent.command, "init");
    assert_eq!(entries[0].intent.by, alice());
    let finished = entries[0].finished.as_ref().unwrap();
    assert_eq!(finished.outcome.result, AuditResult::Ok);
    assert_eq!(finished.outcome.message, "created 8 paths");
}

#[test]
fn init_is_idempotent() {
    let (_dir, engine) = engine();
    done(engine.init(&alice(), Confirm::Ask).unwrap());
    let config = std::fs::read_to_string(engine.layout.config_file()).unwrap();

    let again = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert!(again.created.is_empty());
    assert!(!again.migration.changed());
    assert_eq!(again.summary(), "already initialized; nothing changed");
    let after = std::fs::read_to_string(engine.layout.config_file()).unwrap();
    assert_eq!(config, after);
    assert_eq!(engine.audit(None).unwrap().len(), 2);
    assert!(engine.verify_audit().unwrap().intact());
}

#[test]
fn dry_run_changes_nothing() {
    let (_dir, engine) = engine();
    let planned = engine.init(&alice(), Confirm::DryRun).unwrap();
    assert_eq!(
        planned,
        Planned::DryRun(Plan {
            create: engine.layout.paths(),
            ..Plan::default()
        })
    );
    assert!(!engine.layout.data().exists());
}

#[test]
fn init_records_the_first_available_backend() {
    let (_dir, engine) = engine_with(vec![
        Box::new(FakeBackend::unavailable(
            BackendKind::Libkrun,
            "no VM support",
        )),
        Box::new(FakeBackend::available(BackendKind::Seatbelt)),
    ]);
    let report = done(engine.init(&alice(), Confirm::Ask).unwrap());
    assert_eq!(report.default_backend, Some(BackendKind::Seatbelt));
    assert_eq!(
        report.unavailable,
        [crate::engine::Unavailable {
            backend: BackendKind::Libkrun,
            reason: "no VM support".to_owned(),
        }]
    );
    assert_eq!(report.config_backend, None);
    let config = std::fs::read_to_string(engine.layout.config_file()).unwrap();
    assert!(
        config.contains("default_backend = \"seatbelt\""),
        "{config}"
    );
}

/// A `config.toml` written while no backend was available gets the one
/// available now, in place of init's own line for that; one changed by
/// hand is said to name none and left; one that does not parse is said, and
/// does not fail init.
#[test]
fn init_names_a_backend_in_a_config_written_while_none_was_available() {
    use crate::engine::ConfigBackend;
    let (_dir, mut engine) = engine_with(vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "a bad setting",
    ))]);
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.default_backend, None);
    assert_eq!(report.config_backend, None);
    let written = engine.layout.read_config().unwrap();
    engine.backends = vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))];
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.default_backend, Some(BackendKind::Seatbelt));
    assert!(report.unavailable.is_empty());
    assert_eq!(
        report.config_backend,
        Some(ConfigBackend::Written(BackendKind::Seatbelt))
    );
    assert_eq!(
        engine.layout.read_config().unwrap(),
        crate::config::initial(Some(BackendKind::Seatbelt))
    );
    assert_ne!(engine.layout.read_config().unwrap(), written);
    // Named now: nothing to say.
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(report.config_backend, None);

    // Changed by hand: said, and left as it is.
    let mine = "# mine\nschema_version = 1\n";
    std::fs::write(engine.layout.config_file(), mine).unwrap();
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    assert_eq!(
        report.config_backend,
        Some(ConfigBackend::NotNamed(BackendKind::Seatbelt))
    );
    assert_eq!(engine.layout.read_config().unwrap(), mine);

    // Not TOML: said why, and init still succeeds.
    std::fs::write(engine.layout.config_file(), "not = [toml").unwrap();
    let report = done(engine.init(&alice(), Confirm::Yes).unwrap());
    let Some(ConfigBackend::Unchecked(why)) = &report.config_backend else {
        panic!("{report:?}");
    };
    assert!(why.contains("does not parse"), "{why}");
}

#[test]
fn a_failed_command_closes_its_audit_entry_as_failed() {
    let (_dir, engine) = engine();
    engine.layout.create_roots().unwrap();
    // A file where a folder must go makes init fail half-way.
    std::fs::write(engine.layout.data().join("runtimes"), "").unwrap();

    let err = engine.init(&alice(), Confirm::Ask).unwrap_err();
    assert!(matches!(err, Error::Layout(_)), "{err}");

    let entries = engine.audit(None).unwrap();
    let finished = entries[0].finished.as_ref().unwrap();
    assert_eq!(finished.outcome.result, AuditResult::Failed);
    assert!(finished.outcome.message.contains("runtimes"));
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());
}

#[test]
fn reads_before_init_say_to_run_init() {
    let (_dir, engine) = engine();
    for err in [
        engine.audit(None).unwrap_err(),
        engine.verify_audit().unwrap_err(),
    ] {
        assert!(err.to_string().contains("enclos init"), "{err}");
        assert_eq!(err.exit_code(), 1);
    }
}

#[test]
fn audit_since_keeps_recent_entries() {
    let (_dir, engine) = engine();
    done(engine.init(&alice(), Confirm::Ask).unwrap());
    let recent = engine.audit(Some("1h".parse().unwrap())).unwrap();
    assert_eq!(recent.len(), 1);
}

mod policy {
    use super::*;
    use crate::model::sandbox::SandboxName;

    /// An initialized engine with sandbox `home`, created as the CLI does.
    pub(super) fn with_sandbox() -> (TempDir, Engine, SandboxName) {
        with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt))
    }

    pub(super) fn with_sandbox_on(backend: FakeBackend) -> (TempDir, Engine, SandboxName) {
        let (dir, engine) = engine_with(vec![Box::new(backend)]);
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
}

mod compile {
    use super::policy::with_sandbox_on;
    use super::*;

    #[test]
    fn the_active_policy_compiles_once_into_the_sandbox_folder() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let file = engine.compile_policy(&name, 41001).unwrap();
        assert!(file.starts_with(engine.layout.sandbox_dir("home").join("compiled")));
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .contains("write {home}")
        );
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        // A new grant is a new compiled policy.
        done(
            engine
                .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
                .unwrap(),
        );
        assert_ne!(engine.compile_policy(&name, 41001).unwrap(), file);
    }

    #[test]
    fn a_cut_off_compiled_policy_is_never_reused() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let file = engine.compile_policy(&name, 41001).unwrap();
        let full = std::fs::read_to_string(&file).unwrap();

        // What an interrupted write would have left: a valid start, no end.
        std::fs::write(&file, &full[..full.len() / 2]).unwrap();
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), full);

        // A write that fails, here because a folder stands where the file
        // goes (which fails for root too), leaves nothing of the policy, and
        // the retry succeeds.
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir_all(file.join("in-the-way")).unwrap();
        assert!(engine.compile_policy(&name, 41001).is_err());
        assert!(file.is_dir());
        std::fs::remove_dir_all(&file).unwrap();
        let compiled = file.parent().unwrap();
        assert_eq!(engine.compile_policy(&name, 41001).unwrap(), file);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), full);
        assert_eq!(std::fs::read_dir(compiled).unwrap().count(), 1);
    }

    #[test]
    fn a_backend_this_host_cannot_run_is_refused_and_nothing_is_left() {
        let backend = FakeBackend::unavailable(BackendKind::Seatbelt, "not macOS");
        let (_dir, engine) = engine_with(vec![Box::new(backend)]);
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let spec = crate::engine::SandboxSpec {
            name: "home".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        let err = engine
            .create_sandbox(&alice(), spec, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
        assert_eq!(err.exit_code(), 2);
        assert!(engine.list_sandboxes().unwrap().is_empty());
    }

    /// Puts the sandbox home aside, as the host can, and lets `replace` put
    /// something else at its path.
    fn replace_home(engine: &Engine, replace: impl FnOnce(&std::path::Path)) {
        let home = engine.layout.sandbox_home("home");
        std::fs::rename(&home, home.with_file_name("home-aside")).unwrap();
        replace(&home);
    }

    #[test]
    fn a_home_that_is_not_a_real_folder_is_never_compiled() {
        let outside = std::path::PathBuf::from("/nonexistent-enclos-outside");
        let link_out = |home: &std::path::Path| std::os::unix::fs::symlink(&outside, home).unwrap();
        let a_file = |home: &std::path::Path| std::fs::write(home, "x").unwrap();
        let nothing = |_: &std::path::Path| {};
        for (replace, expected) in [
            (
                &link_out as &dyn Fn(&std::path::Path),
                HomeFound::Link {
                    to: outside.clone(),
                },
            ),
            (&a_file, HomeFound::NotAFolder),
            (&nothing, HomeFound::Missing),
        ] {
            let (_dir, engine, name) =
                with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
            engine.compile_policy(&name, 41001).unwrap();
            replace_home(&engine, replace);
            let err = engine.compile_policy(&name, 41001).unwrap_err();
            assert!(
                matches!(&err, Error::HomeNotAFolder { found, .. } if *found == expected),
                "{expected}: {err}"
            );
            assert!(err.to_string().contains("enclos sandbox rm home"), "{err}");
            assert_eq!(err.exit_code(), 1);
            // `show` and `status` say so: nothing new starts there.
            let shown = engine.show_sandbox(&name).unwrap().policy_refused;
            assert!(shown.is_some_and(|why| why.contains(&expected.to_string())));
        }
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        assert_eq!(engine.show_sandbox(&name).unwrap().policy_refused, None);
        replace_home(&engine, link_out);
        let status = engine.status(Some(&name)).unwrap();
        let refused = status.sandboxes[0].policy_refused.as_deref().unwrap();
        assert!(
            refused.contains("a symbolic link to /nonexistent"),
            "{refused}"
        );
    }

    /// Grants writes to `entries` by hand-editing `policy.toml`, applied by
    /// the next `policy allow`.
    fn grant_writes(engine: &Engine, name: &SandboxName, entries: &str) {
        let file = engine.layout.policy_file(name.as_str());
        let text = std::fs::read_to_string(&file)
            .unwrap()
            .replace("write_add = []", &format!("write_add = [{entries}]"));
        std::fs::write(&file, text).unwrap();
        done(
            engine
                .policy_allow(&alice(), name, "api.example.com", Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn policy_test_probes_each_workspace_once_and_names_one_not_made_yet() {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let user = dir.path().canonicalize().unwrap();
        for d in ["a", "b"] {
            std::fs::create_dir(user.join(d)).unwrap();
        }
        grant_writes(&engine, &name, r#""~/a", "~/b", "~/a/", "~/later""#);
        let ctx = engine.sandbox_context(&name, 41001);
        let inputs = engine
            .probe_inputs(&name, &ctx, None, None, Default::default())
            .unwrap();
        let home = ctx.home.canonicalize().unwrap();
        assert_eq!(inputs.home, home);
        assert_eq!(
            inputs.workspaces,
            [user.join("a"), user.join("b"), user.join("later")]
        );
        let own = FakeBackend::available(BackendKind::Seatbelt)
            .own_probes(None)
            .unwrap();
        let names: Vec<String> = crate::probes::probes(&inputs, own.as_ref())
            .into_iter()
            .filter(|p| p.route == "writable folders")
            .map(|p| p.name)
            .collect();
        let rename = |p: &std::path::Path| format!("rename {}", p.display());
        assert_eq!(
            names,
            [
                "remove the sandbox home".to_owned(),
                rename(&home),
                rename(&user.join("a")),
                rename(&user.join("b")),
            ]
        );
        let missing = crate::probes::missing_workspaces(&inputs);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].name, rename(&user.join("later")));
        assert!(
            matches!(&missing[0].outcome, crate::probes::Outcome::NotRun(why) if why.contains("create it on the host"))
        );
    }

    /// A backend with no probes of its own runs the shared set through its
    /// `wrap`: the fake holds nothing back, so a write and a signal get out
    /// and read open, on what the host sees.
    #[test]
    fn a_fake_backend_s_probes_run_through_the_shared_set() {
        use crate::backend::{Launch, LaunchLimits};
        use crate::probes::{Outcome, probes};
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let backend = engine.backend_of(&name).unwrap();
        let own = backend.own_probes(Some("fake policy for home\n")).unwrap();
        assert_eq!(own.baseline(), None);
        // This test's own child, the signal probe's target.
        let mut target = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let ctx = engine.sandbox_context(&name, 41001);
        let inputs = engine
            .probe_inputs(
                &name,
                &ctx,
                Some(target.id()),
                None,
                LaunchLimits::default(),
            )
            .unwrap();
        let list = probes(&inputs, own.as_ref());
        assert!(own.host_services(&inputs).is_empty());
        for route in ["writes", "signals"] {
            let probe = list.iter().find(|p| p.route == route).unwrap();
            let got = crate::engine::probe::run_probe(
                probe,
                |script| {
                    let launch = Launch {
                        program: "/bin/sh".into(),
                        args: vec!["-c".into(), script.into()],
                        env: Vec::new(),
                        in_terminal: false,
                        service_port: None,
                        limits: LaunchLimits::default(),
                    };
                    backend
                        .wrap(std::path::Path::new("unused"), &ctx, &launch)
                        .stdin(std::process::Stdio::null())
                        .output()
                },
                &mut target,
            );
            assert!(matches!(got, Outcome::Open(_)), "{route}: {got:?}");
        }
        let _ = target.kill();
        let _ = target.wait();
    }

    #[test]
    fn the_write_rules_are_checked_again_as_the_paths_are_when_compiled() {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        grant_writes(&engine, &name, "\"~/work\"");
        assert!(
            engine
                .policy(&name)
                .unwrap()
                .snapshot
                .policy
                .fs
                .write
                .contains(&"~/work".into())
        );
        engine.compile_policy(&name, 41001).unwrap();

        // The host points the workspace at enclos's own folder afterwards.
        std::fs::remove_dir(&work).unwrap();
        std::os::unix::fs::symlink(engine.layout.data(), &work).unwrap();
        let err = engine.compile_policy(&name, 41001).unwrap_err();
        assert!(matches!(err, Error::ActivePolicyInvalid { .. }), "{err}");
        assert!(err.to_string().contains("enclos's own files"), "{err}");
        assert_eq!(err.exit_code(), 1);

        // Or through a link in the sandbox home, which the sandbox can
        // point anywhere before the next compile.
        std::fs::remove_file(&work).unwrap();
        let in_home = engine.layout.sandbox_home("home").join("out");
        std::os::unix::fs::symlink(dir.path(), &in_home).unwrap();
        std::os::unix::fs::symlink(&in_home, &work).unwrap();
        let err = engine.compile_policy(&name, 41001).unwrap_err();
        assert!(matches!(err, Error::ActivePolicyInvalid { .. }), "{err}");
        assert!(err.to_string().contains("through a link"), "{err}");
    }

    /// With macOS's own Seatbelt: the sandbox cannot put a link in place of
    /// its home, and when the host does, the policy is not compiled.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_sandbox_cannot_swap_its_home_and_a_swapped_home_is_never_compiled() {
        use crate::backend::Launch;
        use crate::backend::seatbelt::Seatbelt;

        let (dir, engine) = engine_with(vec![Box::new(Seatbelt::default())]);
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "home".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        let compiled = engine.compile_policy(&name, 41001).unwrap();
        let home = engine.layout.sandbox_home("home");
        let outside = dir.path().canonicalize().unwrap();
        let swap = format!(
            "/bin/rmdir \"$HOME/tmp\"; /bin/rmdir \"$HOME\" && /bin/ln -s '{}' \"$HOME\"",
            outside.display()
        );
        let launch = Launch {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), swap.into()],
            env: Vec::new(),
            in_terminal: false,
            service_port: None,
            limits: Default::default(),
        };
        let ctx = engine.sandbox_context(&name, 41001);
        let out = Seatbelt::default()
            .wrap(&compiled, &ctx, &launch)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(stderr.contains("Operation not permitted"), "{stderr}");
        let meta = home.symlink_metadata().unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());

        replace_home(&engine, |home| {
            std::os::unix::fs::symlink(&outside, home).unwrap();
        });
        let err = engine.compile_policy(&name, 41001).unwrap_err();
        assert!(
            matches!(&err, Error::HomeNotAFolder { found: HomeFound::Link { to }, .. } if *to == outside),
            "{err}"
        );
    }
}

mod sandbox {
    use super::policy::with_sandbox_on;
    use super::*;
    use crate::engine::SandboxSpec;
    use crate::lifecycle::process::reference;
    use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
    use crate::model::session::{ProcessRef, SessionId, SessionKind, SessionRecord};

    fn spec(name: &str) -> SandboxSpec {
        SandboxSpec {
            name: name.parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        }
    }

    #[test]
    fn each_sandbox_gets_its_own_port_and_names_are_unique() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let lab = done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
        let home = engine
            .show_sandbox(&"home".parse().unwrap())
            .unwrap()
            .record;
        // A port another program listens on is skipped (other tests run
        // proxies in the same range), so which port each gets is not fixed:
        // only that each has its own, in the range.
        let range = crate::model::sandbox::PORT_FIRST..=crate::model::sandbox::PORT_LAST;
        assert!(range.contains(&home.proxy_port) && range.contains(&lab.proxy_port));
        assert_ne!(home.proxy_port, lab.proxy_port);
        let err = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxExists { .. }), "{err}");
        assert_eq!(engine.list_sandboxes().unwrap().len(), 2);
    }

    #[test]
    fn removing_asks_first_and_deletes_the_folder() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let dir = engine.layout.sandbox_dir("home");
        assert!(dir.join("policy.toml").exists());
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
        assert!(!dir.exists());
        assert!(engine.list_sandboxes().unwrap().is_empty());
    }

    /// Runs `work` while another command holds the state lock: `work`
    /// passes its checks and waits, then `meanwhile` changes the state
    /// before the lock is released.
    pub(super) fn while_waiting<T>(
        engine: &Engine,
        work: impl FnOnce() -> T,
        meanwhile: impl FnOnce(&Engine, &crate::state::StateLock) + Send,
    ) -> T {
        let layout = engine.layout.clone();
        let (held, wait) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let other = Engine::open(layout);
                let lock = other.state.lock().unwrap();
                held.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                meanwhile(&other, &lock);
            });
            wait.recv().unwrap();
            work()
        })
    }

    #[test]
    fn a_create_that_waited_for_the_lock_checks_the_name_again() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let first = SandboxRecord {
            name: "lab".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            created_from: "assistant".parse().unwrap(),
            state: SandboxState::Created,
            proxy_port: 1,
            runtime: None,
            created_at: crate::model::now(),
        };
        let err = while_waiting(
            &engine,
            || engine.create_sandbox(&alice(), spec("lab"), Confirm::Yes),
            |other, lock| other.state.put(lock, &first).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::SandboxExists { .. }), "{err}");
        let lab = engine.state.get(&first.name).unwrap().unwrap();
        assert_eq!(lab.proxy_port, 1);
    }

    /// An interactive session of sandbox `name` whose program is `root`.
    pub(super) fn session_of(
        engine: &Engine,
        name: &SandboxName,
        root: ProcessRef,
    ) -> SessionRecord {
        SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind: SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: engine.policy(name).unwrap().snapshot.id,
            compiled: None,
            root,
            pgid: None,
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        }
    }

    /// A process this test started and reaped: nothing runs as that process
    /// any more (its pid is free, or used again with another start time), as
    /// a session's after a crash or a restart of the Mac.
    pub(super) fn gone_process() -> ProcessRef {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let recorded = crate::lifecycle::process::reference_of_child(&child).unwrap();
        child.wait().unwrap();
        recorded
    }

    /// A `sleep` this test started, ended and reaped when dropped.
    pub(super) struct Sleeping(std::process::Child);

    impl Sleeping {
        pub(super) fn new() -> Sleeping {
            Sleeping(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            )
        }

        pub(super) fn process(&self) -> ProcessRef {
            reference(self.0.id()).unwrap().unwrap()
        }
    }

    impl Drop for Sleeping {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn mark(engine: &Engine, name: &SandboxName, state: SandboxState) {
        let lock = engine.state.lock().unwrap();
        let mut record = engine.state.get(name).unwrap().unwrap();
        record.state = state;
        engine.state.put(&lock, &record).unwrap();
    }

    pub(super) fn put(engine: &Engine, session: &SessionRecord) -> SessionId {
        // As a session's start makes it, for its marker, when it can (a
        // test may have put something else there).
        let _ = std::fs::create_dir_all(engine.markers(&session.sandbox));
        let lock = engine.state.lock().unwrap();
        engine.state.put_session(&lock, session).unwrap()
    }

    #[test]
    fn a_remove_that_waited_for_the_lock_checks_for_sessions_again() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let sleeping = Sleeping::new();
        let session = session_of(&engine, &name, sleeping.process());
        let err = while_waiting(
            &engine,
            || engine.remove_sandbox(&alice(), &name, false, Confirm::Yes),
            |other, lock| {
                other.state.put_session(lock, &session).unwrap();
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::SandboxRunning { .. }), "{err}");
        assert!(engine.layout.sandbox_home("home").is_dir());
    }

    #[test]
    fn show_and_status_say_a_session_is_gone_and_record_nothing() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        mark(&engine, &name, SandboxState::Running);
        let sleeping = Sleeping::new();
        let live = put(&engine, &session_of(&engine, &name, sleeping.process()));
        let gone = put(&engine, &session_of(&engine, &name, gone_process()));
        let entries = engine.audit(None).unwrap().len();

        let view = engine.show_sandbox(&name).unwrap();
        let shown: Vec<(SessionId, bool)> = view
            .sessions
            .iter()
            .map(|v| (v.session.id, v.gone()))
            .collect();
        assert_eq!(shown, [(live, false), (gone, true)]);
        let status = engine.status(None).unwrap();
        let home = &status.sandboxes[0];
        assert_eq!((home.running_sessions, home.gone_sessions), (1, 1));

        // Reads: the sessions stay open, the sandbox running, the audit log
        // as it was.
        assert_eq!(engine.state.sessions(&name, true).unwrap().len(), 2);
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    fn state_of(engine: &Engine, name: &SandboxName) -> SandboxState {
        engine.state.get(name).unwrap().unwrap().state
    }

    fn last_audit(engine: &Engine) -> String {
        let entries = engine.audit(None).unwrap();
        let finished = entries.last().unwrap().finished.as_ref().unwrap();
        assert_eq!(finished.outcome.result, AuditResult::Ok);
        finished.outcome.message.clone()
    }

    #[test]
    fn rm_records_the_end_of_sessions_gone_after_a_crash_and_removes_the_sandbox() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        mark(&engine, &name, SandboxState::Running);
        let sleeping = Sleeping::new();
        let live = put(&engine, &session_of(&engine, &name, sleeping.process()));
        let gone = put(&engine, &session_of(&engine, &name, gone_process()));

        // While one session still runs, nothing is removed or recorded.
        let entries = engine.audit(None).unwrap().len();
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxRunning { .. }), "{err}");
        assert_eq!(engine.state.sessions(&name, true).unwrap().len(), 2);
        assert_eq!(engine.audit(None).unwrap().len(), entries);

        // Once it is gone too, rm records both ends, in its audit entry.
        drop(sleeping);
        let Planned::DryRun(plan) = engine
            .remove_sandbox(&alice(), &name, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed the sandbox");
        };
        assert_eq!(
            plan.changes[..2],
            [
                format!("record the end of session {live}, whose processes are gone"),
                format!("record the end of session {gone}, whose processes are gone"),
            ]
        );
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
        assert!(engine.list_sandboxes().unwrap().is_empty());
        assert_eq!(
            last_audit(&engine),
            format!(
                "delete its folder and home; recorded the end of sessions {live}, {gone}, whose processes were gone"
            )
        );
    }

    /// Another engine on `engine`'s folder, on which the sandboxes' backend
    /// no longer runs: whatever starts a session fails half-way.
    pub(super) fn without_backend(engine: &Engine) -> Engine {
        let layout = engine.layout.clone();
        Engine::new(
            layout.clone(),
            Box::new(SqliteStateStore::new(
                layout.state_db(),
                layout.state_lock(),
            )),
            Box::new(JsonlAuditLog::new(layout.audit_log())),
            vec![Box::new(FakeBackend::unavailable(
                BackendKind::Seatbelt,
                "taken away by the test",
            ))],
        )
    }

    /// The sandbox is marked failed by `command`, whose audit entry closed
    /// as failed, and no session but the proxy's was recorded.
    pub(super) fn assert_failed_by(engine: &Engine, name: &SandboxName, command: &str) {
        match state_of(engine, name) {
            SandboxState::Failed { reason } => assert!(
                reason.starts_with(&format!("{command} failed: "))
                    && reason.contains("taken away by the test"),
                "{reason}"
            ),
            other => panic!("{other:?}"),
        }
        let entries = engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, command);
        let finished = last.finished.as_ref().unwrap();
        assert_eq!(finished.outcome.result, AuditResult::Failed);
        assert!(
            engine
                .state
                .sessions(name, false)
                .unwrap()
                .iter()
                .all(|s| s.kind == SessionKind::Proxy)
        );
    }

    #[test]
    fn a_connect_that_fails_marks_the_sandbox_failed_in_its_audited_write() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let err = without_backend(&engine)
            .connect(&alice(), &name, vec!["/usr/bin/true".into()], Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
        assert_failed_by(&engine, &name, "connect");
        // A connect to no sandbox has nothing to mark.
        let err = engine
            .connect(&alice(), &"nope".parse().unwrap(), Vec::new(), Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
    }

    #[test]
    fn stop_records_the_end_of_a_session_gone_after_a_crash_and_marks_the_sandbox_stopped() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        mark(&engine, &name, SandboxState::Running);
        let gone = put(&engine, &session_of(&engine, &name, gone_process()));
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(report.gone, [gone]);
        assert!(report.stopped.is_empty() && report.survivors.is_empty());
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
        assert_eq!(
            last_audit(&engine),
            format!(
                "removed 0 services, stopped 0 sessions; recorded the end of sessions {gone}, whose processes were gone"
            )
        );
    }

    #[test]
    fn stop_ends_a_session_still_running_and_records_one_gone_beside_it() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        mark(&engine, &name, SandboxState::Running);
        let mut sleeping = Sleeping::new();
        let live = put(&engine, &session_of(&engine, &name, sleeping.process()));
        let gone = put(&engine, &session_of(&engine, &name, gone_process()));
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(report.stopped, [live]);
        assert_eq!(report.gone, [gone]);
        assert!(report.survivors.is_empty());
        // The sleep was signalled: it exited by TERM.
        let status = sleeping
            .0
            .try_wait()
            .unwrap()
            .expect("the sleep still runs");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(15));
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
        assert_eq!(
            last_audit(&engine),
            format!(
                "removed 0 services, stopped 1 sessions; recorded the end of sessions {gone}, whose processes were gone"
            )
        );
    }

    #[test]
    fn a_connect_that_fails_beside_a_running_session_makes_rm_say_why() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        mark(&engine, &name, SandboxState::Running);
        let sleeping = Sleeping::new();
        put(&engine, &session_of(&engine, &name, sleeping.process()));
        without_backend(&engine)
            .connect(&alice(), &name, vec!["/usr/bin/true".into()], Confirm::Yes)
            .unwrap_err();
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        let Error::SandboxNotStopped { reason, .. } = &err else {
            panic!("{err}");
        };
        assert!(reason.starts_with("connect failed: "), "{reason}");
        assert!(err.to_string().contains("connect failed: "), "{err}");
        drop(sleeping);
    }

    /// A dry run refuses the template a create would refuse, and writes
    /// nothing.
    #[test]
    fn a_dry_run_create_refuses_an_unknown_template() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let mut bad = spec("lab");
        bad.template = "does-not-exist".parse().unwrap();
        let err = engine
            .create_sandbox(&alice(), bad, Confirm::DryRun)
            .unwrap_err();
        assert!(err.to_string().contains("unknown template"), "{err}");
        assert!(!engine.layout.sandbox_dir("lab").exists());
        let planned = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::DryRun)
            .unwrap();
        assert!(matches!(planned, Planned::DryRun(_)), "{planned:?}");
        assert!(!engine.layout.sandbox_dir("lab").exists());
    }

    /// A dry run says a `policy.toml` kept in the sandbox's folder is
    /// written again, and refuses one the create could not read.
    #[test]
    fn a_dry_run_create_says_what_it_does_with_a_kept_folder() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine.layout.create_sandbox_dirs("lab").unwrap();
        engine.layout.write_policy("lab", "# kept\n").unwrap();
        let Planned::DryRun(plan) = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::DryRun)
            .unwrap()
        else {
            panic!("expected a plan")
        };
        assert!(
            plan.changes[1]
                .starts_with("write its policy.toml again from the `assistant` template"),
            "{plan:?}"
        );
        assert_eq!(engine.layout.read_policy("lab").unwrap(), "# kept\n");
        let file = engine.layout.policy_file("lab");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        engine
            .create_sandbox(&alice(), spec("lab"), Confirm::DryRun)
            .unwrap_err();
    }

    /// `sandbox list` and `show` name the template the active policy is
    /// built on, once `policy.toml` names another than the sandbox was
    /// created from.
    #[test]
    fn a_sandbox_is_shown_with_the_template_its_active_policy_is_built_on() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let file = engine.layout.policy_file(name.as_str());
        let before = std::fs::read_to_string(&file).unwrap();
        let after = before.replace("extends = \"assistant\"", "extends = \"minimal\"");
        assert_ne!(before, after);
        done(
            engine
                .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
                .unwrap(),
        );
        let view = engine.show_sandbox(&name).unwrap();
        assert_eq!(view.record.created_from.as_str(), "assistant");
        assert_eq!(view.template.as_str(), "minimal");
        assert_eq!(
            engine.list_sandboxes().unwrap()[0].template.as_str(),
            "minimal"
        );
    }

    #[test]
    fn a_create_with_an_unknown_template_leaves_nothing() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let mut bad = spec("lab");
        bad.template = "does-not-exist".parse().unwrap();
        engine
            .create_sandbox(&alice(), bad, Confirm::Yes)
            .unwrap_err();
        assert!(!engine.layout.sandbox_dir("lab").exists());
        assert_eq!(engine.list_sandboxes().unwrap().len(), 1);
        done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn a_failed_create_keeps_a_folder_kept_by_remove() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        done(
            engine
                .remove_sandbox(&alice(), &name, true, Confirm::Yes)
                .unwrap(),
        );
        let home = engine.layout.sandbox_home("home");
        std::fs::write(home.join("notes"), "kept").unwrap();
        let mut bad = spec("home");
        bad.template = "does-not-exist".parse().unwrap();
        engine
            .create_sandbox(&alice(), bad, Confirm::Yes)
            .unwrap_err();
        assert_eq!(std::fs::read_to_string(home.join("notes")).unwrap(), "kept");
    }

    #[test]
    fn a_create_whose_records_fail_leaves_what_was_there_before() {
        let (_dir, engine, home) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        done(
            engine
                .remove_sandbox(&alice(), &home, true, Confirm::Yes)
                .unwrap(),
        );
        engine.layout.write_policy("home", "kept = true\n").unwrap();
        // The policy version fails, and a record cannot be deleted either:
        // only a create that writes both in one transaction leaves no
        // record, since one that committed the record first could not take
        // it back, as after a crash between the two.
        let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_policy BEFORE INSERT ON policy_versions
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;
             CREATE TRIGGER no_cleanup BEFORE DELETE ON sandboxes
             BEGIN SELECT RAISE(ABORT, 'cleanup cannot run'); END;",
        )
        .unwrap();
        let err = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("injected failure"), "{err}");
        let lab: SandboxName = "lab".parse().unwrap();
        assert_eq!(engine.state.get(&lab).unwrap(), None);
        assert!(!engine.layout.sandbox_dir("lab").exists());
        // A folder kept by `rm --keep-data` keeps its `policy.toml`.
        engine
            .create_sandbox(&alice(), spec("home"), Confirm::Yes)
            .unwrap_err();
        assert_eq!(engine.state.get(&home).unwrap(), None);
        assert_eq!(engine.layout.read_policy("home").unwrap(), "kept = true\n");
        conn.execute_batch("DROP TRIGGER fail_policy; DROP TRIGGER no_cleanup")
            .unwrap();
        done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn a_create_that_fails_in_a_folder_without_policy_toml_takes_back_only_that_file() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        // A folder left by a create that stopped before writing its policy.
        engine.layout.create_sandbox_dirs("lab").unwrap();
        let notes = engine.layout.sandbox_home("lab").join("notes");
        std::fs::write(&notes, "kept").unwrap();
        let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_policy BEFORE INSERT ON policy_versions
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        let err = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("injected failure"), "{err}");
        let lab: SandboxName = "lab".parse().unwrap();
        assert_eq!(engine.state.get(&lab).unwrap(), None);
        assert!(!engine.layout.policy_file("lab").exists());
        assert_eq!(std::fs::read_to_string(&notes).unwrap(), "kept");
    }

    #[test]
    fn a_kept_policy_toml_that_cannot_be_read_stops_the_create_before_it_writes() {
        let (_dir, engine, home) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        done(
            engine
                .remove_sandbox(&alice(), &home, true, Confirm::Yes)
                .unwrap(),
        );
        // Not UTF-8: a failed create could not put it back.
        let file = engine.layout.policy_file("home");
        std::fs::write(&file, b"kept = \"\xff\"\n").unwrap();
        let err = engine
            .create_sandbox(&alice(), spec("home"), Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::Layout(_)), "{err}");
        assert_eq!(engine.state.get(&home).unwrap(), None);
        assert_eq!(std::fs::read(&file).unwrap(), b"kept = \"\xff\"\n");
    }

    #[test]
    fn a_folder_left_by_a_create_that_stopped_before_its_records_is_reused() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        // What create writes before its transaction.
        engine.layout.create_sandbox_dirs("lab").unwrap();
        engine
            .layout
            .write_policy("lab", "left = \"over\"\n")
            .unwrap();
        let lab: SandboxName = "lab".parse().unwrap();
        // Not listed, and, as of today, not something `rm` knows.
        let listed = engine.list_sandboxes().unwrap();
        assert!(listed.iter().all(|v| v.record.name != lab));
        assert!(matches!(
            engine.remove_sandbox(&alice(), &lab, true, Confirm::Yes),
            Err(Error::NoSuchSandbox { .. })
        ));
        done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(engine.policy(&lab).unwrap().version.version, 1);
        let file = engine.layout.read_policy("lab").unwrap();
        assert!(!file.contains("left"), "{file}");
    }

    #[test]
    fn a_sandbox_without_an_active_policy_says_how_to_create_it_again() {
        let (_dir, engine, _) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        // A record with no policy version, which enclos never writes but an
        // older build could leave.
        let lab = SandboxRecord {
            name: "lab".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            created_from: "assistant".parse().unwrap(),
            state: SandboxState::Created,
            proxy_port: 1,
            runtime: None,
            created_at: crate::model::now(),
        };
        engine
            .state
            .put(&engine.state.lock().unwrap(), &lab)
            .unwrap();
        engine.layout.create_sandbox_dirs("lab").unwrap();
        let notes = engine.layout.sandbox_home("lab").join("notes");
        std::fs::write(&notes, "kept").unwrap();

        let err = engine.policy(&lab.name).unwrap_err();
        assert!(matches!(err, Error::NoPolicy { .. }), "{err}");
        let message = err.to_string();
        assert!(!message.contains("state check"), "{message}");
        assert!(
            message.contains("`enclos sandbox rm lab --keep-data`")
                && message.contains(
                    "`enclos sandbox create lab --backend seatbelt --template assistant`"
                ),
            "{message}"
        );
        // It makes the sandbox again from its own backend and template, not
        // the defaults of `sandbox create`.
        let work = SandboxRecord {
            name: "work".parse().unwrap(),
            backend: BackendKind::Bubblewrap,
            created_from: "coding".parse().unwrap(),
            ..lab.clone()
        };
        engine
            .state
            .put(&engine.state.lock().unwrap(), &work)
            .unwrap();
        let message = engine.policy(&work.name).unwrap_err().to_string();
        assert!(
            message.contains("`enclos sandbox create work --backend bubblewrap --template coding`"),
            "{message}"
        );

        // The steps it names work, without --yes, and keep the home.
        done(
            engine
                .remove_sandbox(&alice(), &lab.name, true, Confirm::Ask)
                .unwrap(),
        );
        done(
            engine
                .create_sandbox(&alice(), spec("lab"), Confirm::Ask)
                .unwrap(),
        );
        assert_eq!(engine.policy(&lab.name).unwrap().version.version, 1);
        assert_eq!(std::fs::read_to_string(&notes).unwrap(), "kept");
    }

    #[test]
    fn dry_runs_of_stop_and_connect_change_nothing() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = engine
            .stop_sandbox(&alice(), &name, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run stopped the sandbox");
        };
        assert_eq!(plan.changes, ["mark sandbox home stopped"]);
        let Planned::DryRun(plan) = engine
            .connect(&alice(), &name, Vec::new(), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run connected");
        };
        assert!(
            plan.changes.last().is_some_and(
                |c| c.starts_with(&format!("run `{}` in sandbox home", default_shell()))
            ),
            "{plan:?}"
        );
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            crate::model::sandbox::SandboxState::Created
        );
        assert!(engine.state.sessions(&name, false).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn dry_runs_of_create_and_rm_change_nothing() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let Planned::DryRun(_) = engine
            .create_sandbox(&alice(), spec("lab"), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run created a sandbox");
        };
        let Planned::DryRun(_) = engine
            .remove_sandbox(&alice(), &name, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed a sandbox");
        };
        assert!(!engine.layout.sandbox_dir("lab").exists());
        assert!(engine.layout.sandbox_home("home").is_dir());
        assert_eq!(engine.list_sandboxes().unwrap().len(), 1);
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn members_a_stop_cannot_end_fail_the_sandbox_until_they_are_gone() {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        // A program in a group made for it, which leaves a sleep there and
        // exits once its input closes: the sleep is only counted.
        let mut program = std::process::Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 & read line"])
            .stdin(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind: SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: engine.policy(&name).unwrap().snapshot.id,
            compiled: None,
            root: reference(program.id()).unwrap().unwrap(),
            pgid: Some(program.id()),
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        let lock = engine.state.lock().unwrap();
        let id = engine.state.put_session(&lock, &session).unwrap();
        drop(lock);
        let start = std::time::Instant::now();
        let sleep = loop {
            let view = engine.show_sandbox(&name).unwrap();
            if let Some(m) = view.sessions[0]
                .members
                .iter()
                .find(|m| m.pid != program.id())
            {
                break m.clone();
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        program.stdin.take().unwrap().write_all(b"\n").unwrap();
        program.wait().unwrap();

        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert!(report.stopped.is_empty());
        let survivors = &report.survivors;
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors[0].0, id);
        assert_eq!(survivors[0].1[0].member, sleep);
        assert_eq!(
            survivors[0].1[0].why,
            crate::lifecycle::stop::Why::NotSignalled
        );
        assert!(matches!(
            engine.show_sandbox(&name).unwrap().record.state,
            SandboxState::Failed { .. }
        ));
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxNotStopped { .. }), "{err}");

        // Once the user ends it, stop finds nothing of the session left and
        // records its end.
        let sleep = ProcessRef {
            pid: sleep.pid,
            started: sleep.started,
        };
        crate::lifecycle::process::signal_process(&sleep, crate::lifecycle::process::Signal::Kill)
            .unwrap();
        let start = std::time::Instant::now();
        while crate::lifecycle::process::is_same(&sleep).unwrap() {
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(report.gone, [id]);
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            SandboxState::Stopped
        );
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn stopping_a_sandbox_with_nothing_running_marks_it_stopped() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert!(report.stopped.is_empty() && report.survivors.is_empty());
        assert_eq!(
            engine.show_sandbox(&name).unwrap().record.state,
            crate::model::sandbox::SandboxState::Stopped
        );
    }
}

mod runtime {
    use super::policy::with_sandbox_on;
    use super::*;
    use crate::model::agent::{AgentName, AgentRecord};
    use crate::model::runtime::RuntimeKind;
    use crate::runtime::RuntimeAgentName;
    use crate::runtime::{
        HomeFile, Installer, RuntimeAdapter, SandboxCommand, Unreadable, hermes::Hermes,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    #[test]
    fn an_installed_runtime_adds_its_endpoints_as_a_new_policy_version() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    let overrides = engine.layout.read_policy("home")?;
                    engine.checked_policy(&name, &overrides).and_then(|s| {
                        engine.store_policy(lock, &alice(), &name, &overrides, &s, None)
                    })
                },
            )
            .unwrap();
        let view = engine.policy(&name).unwrap();
        assert_eq!(view.version.version, 2);
        assert!(
            view.snapshot
                .policy
                .net
                .allow
                .contains(&"chatgpt.com".to_owned())
        );
        assert_eq!(
            view.snapshot.inputs.adapter.as_ref().unwrap().runtime,
            "hermes"
        );
        // The adapter adds destinations and nothing else.
        let first = engine.state.policy_history(&name).unwrap()[0].clone();
        assert_eq!(first.version, 1);
        assert_eq!(view.snapshot.policy.fs.write, ["{home}"]);
        assert!(
            view.snapshot
                .policy
                .fs
                .read_deny
                .iter()
                .any(|p| p == "~/.ssh")
        );
    }

    #[test]
    fn saving_the_active_policy_again_adds_no_version() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        for _ in 0..2 {
            engine
                .write(
                    &alice(),
                    "test",
                    None,
                    |_| String::new(),
                    |lock| {
                        let overrides = engine.layout.read_policy("home")?;
                        engine.checked_policy(&name, &overrides).and_then(|s| {
                            engine.store_policy(lock, &alice(), &name, &overrides, &s, None)
                        })
                    },
                )
                .unwrap();
        }
        assert_eq!(engine.policy(&name).unwrap().version.version, 1);
        assert_eq!(engine.state.policy_history(&name).unwrap().len(), 1);
    }

    #[test]
    fn agents_need_a_runtime_first() {
        let (_dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let err = engine.agents(&name).unwrap_err();
        assert!(err.to_string().contains("no runtime yet"), "{err}");
        assert!(
            err.to_string()
                .contains("enclos runtime install hermes --sandbox home"),
            "{err}"
        );
    }

    /// Hermes's adapter with an installer of the test's own: `url` is a
    /// `file://` URL to it and `sha256` its hash, which the audit entry should
    /// name.
    struct TestRuntime {
        url: String,
        sha256: String,
    }

    impl TestRuntime {
        fn new(dir: &Path, script: &str) -> TestRuntime {
            let installer = dir.join("install.sh");
            std::fs::write(&installer, script).unwrap();
            let digest = <sha2::Sha256 as sha2::Digest>::digest(script.as_bytes());
            let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
            TestRuntime {
                url: format!("file://{}", installer.display()),
                sha256,
            }
        }
    }

    impl RuntimeAdapter for TestRuntime {
        fn kind(&self) -> RuntimeKind {
            RuntimeKind::Hermes
        }
        fn version(&self) -> &'static str {
            Hermes.version()
        }
        fn endpoints(&self) -> &'static str {
            Hermes.endpoints()
        }
        fn installer(&self) -> Installer {
            Installer {
                url: self.url.clone(),
                args: vec!["--non-interactive".into()],
            }
        }
        fn home_files(&self) -> Vec<HomeFile> {
            Hermes.home_files()
        }
        fn login(&self) -> String {
            Hermes.login()
        }
        fn create_agent(&self, name: &AgentName) -> SandboxCommand {
            Hermes.create_agent(name)
        }
        fn agent_files(&self, name: &AgentName) -> String {
            Hermes.agent_files(name)
        }
        fn talk(&self, agent: &AgentName) -> String {
            Hermes.talk(agent)
        }
        fn services(&self) -> Vec<crate::runtime::RuntimeService> {
            Hermes.services()
        }
        fn agents_in(&self, home: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
            Hermes.agents_in(home)
        }
    }

    /// An installer that puts a `hermes` stub on the sandbox's PATH, which
    /// records its calls in the home and fails while `hermes-fails` exists.
    const INSTALLS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
printf '%s\\n' \"$*\" >> \"$HOME/hermes-calls\"
[ -f \"$HOME/hermes-fails\" ] && exit 3
[ -f \"$HOME/hermes-token-fails\" ] && [ \"$5\" = platforms.telegram.token ] && exit 3
[ -f \"$HOME/hermes-after-fails\" ] && [ \"$5\" = secrets.command.enabled ] && exit 3
if [ \"$1 $2\" = \"profile delete\" ] && [ ! -f \"$HOME/hermes-keeps\" ]; then
  rm -rf \"$HOME/.hermes/profiles/$3\"
fi
[ \"$2\" = import ] && cat \"$3\" > \"$HOME/imported-$5\"
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
echo \"installed $*\" > \"$HOME/installed\"
";

    /// The number of `SIGUSR1`, which differs between the two systems.
    const USR1: i32 = if cfg!(target_os = "macos") { 30 } else { 10 };

    /// Engine tests start real proxies on this host's ports: one at a time,
    /// with every other test run of this user too.
    static HOST_PORTS: crate::host_ports::HostPorts = crate::host_ports::HostPorts;

    /// `ask` again while it is `None`, the lock busy, as a service's wait
    /// loop asks again: another test's child, forked while this test held
    /// the state lock, holds a copy of its descriptor until it execs, and so
    /// the lock, a moment after this test dropped it.
    fn answered<T>(mut ask: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let asked = ask();
            if asked.is_some() || std::time::Instant::now() > deadline {
                return asked;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A sandbox whose proxy is a listener this test stands in (`nc`), so
    /// that sessions can run through the fake backend; stopped when dropped,
    /// so the listener never outlives the test.
    struct Lab {
        _dir: TempDir,
        engine: Engine,
        name: SandboxName,
        home: PathBuf,
    }

    impl Lab {
        fn new() -> Lab {
            Lab::with_services(None)
        }

        /// A lab whose engine installs services through `services`.
        fn with_services(services: Option<Box<dyn crate::service::ServiceManager>>) -> Lab {
            Lab::build(services, None, None)
        }

        /// A lab whose `launch` stops a session's members with `stop` once
        /// told to end.
        fn stopping_with(stop: crate::engine::StopMembers) -> Lab {
            Lab::build(None, Some(stop), None)
        }

        /// A lab whose engine keeps secrets in `secrets`.
        fn with_secrets(secrets: Box<dyn crate::secrets::SecretStore>) -> Lab {
            Lab::build(None, None, Some(secrets))
        }

        fn build(
            services: Option<Box<dyn crate::service::ServiceManager>>,
            stop: Option<crate::engine::StopMembers>,
            secrets: Option<Box<dyn crate::secrets::SecretStore>>,
        ) -> Lab {
            let (dir, engine, name) =
                with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
            let engine = match services {
                Some(services) => engine.with_services(services),
                None => engine,
            };
            let engine = match secrets {
                Some(secrets) => engine.with_secrets(secrets),
                None => engine,
            };
            let engine = match stop {
                Some(stop) => engine.with_stop_members(stop),
                None => engine,
            };
            let proxy = dir.path().join("proxy.sh");
            std::fs::write(
                &proxy,
                "#!/bin/sh\necho \"fake proxy on port $5\" >&2\nexec /usr/bin/nc -lk 127.0.0.1 \"$5\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o700)).unwrap();
            let home = engine.layout.sandbox_home("home");
            Lab {
                _dir: dir,
                engine: engine.with_exe(proxy),
                name,
                home,
            }
        }

        fn install(&self, script: &str, confirm: Confirm) -> Result<Planned<InstallEnd>> {
            let runtime = TestRuntime::new(self._dir.path(), script);
            self.engine
                .install_runtime_with(&alice(), &self.name, &runtime, confirm)
        }

        fn runtime(&self) -> Option<RuntimeKind> {
            self.engine.state.get(&self.name).unwrap().unwrap().runtime
        }

        fn allows(&self, host: &str) -> bool {
            self.engine
                .policy(&self.name)
                .unwrap()
                .snapshot
                .policy
                .net
                .allow
                .contains(&host.to_owned())
        }

        fn audit(&self) -> String {
            self.engine
                .audit(None)
                .unwrap()
                .iter()
                .map(|e| format!("{} {:?}", e.intent.command, e.finished))
                .collect::<Vec<_>>()
                .join("\n")
        }

        /// The summary of the last finished audit entry for `command`.
        fn summary(&self, command: &str) -> String {
            self.engine
                .audit(None)
                .unwrap()
                .into_iter()
                .rfind(|e| e.intent.command == command)
                .and_then(|e| e.finished)
                .map(|f| f.outcome.message)
                .unwrap_or_else(|| panic!("no finished {command} entry"))
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = self.engine.stop_sandbox(&alice(), &self.name, Confirm::Yes);
        }
    }

    #[test]
    fn a_dry_run_of_an_install_says_what_it_would_change_and_changes_nothing() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let entries = lab.engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
            panic!("a dry run installed");
        };
        let plan = plan.changes.join("\n");
        assert!(
            plan.contains("allow the 13 destinations hermes needs"),
            "{plan}"
        );
        // Listening is what the adapter brings, like its destinations: named,
        // and not an "also" change that would ask first (ADR 0028).
        assert!(
            plan.contains("let sandbox home listen on TCP for hermes"),
            "{plan}"
        );
        assert!(!plan.contains("also "), "{plan}");
        assert!(
            plan.contains("download the hermes installer from file://"),
            "{plan}"
        );
        assert!(plan.contains("start the proxy"), "{plan}");
        assert_eq!(lab.engine.audit(None).unwrap().len(), entries);
        assert_eq!(lab.runtime(), None);
        assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
        assert!(!lab.home.join("bin/mktemp").exists());
    }

    /// `policy.toml` keeping listening off wins over the adapter, and the
    /// plan says Hermes's gateway then cannot start (ADR 0028).
    #[test]
    fn an_install_says_when_policy_toml_keeps_listening_off() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let toml = lab.engine.layout.read_policy("home").unwrap();
        let off = toml.replace("[network]", "[network]\nlisten = false");
        lab.engine.layout.write_policy("home", &off).unwrap();
        let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
            panic!("a dry run installed");
        };
        let plan = plan.changes.join("\n");
        assert!(
            plan.contains("keep sandbox home from listening, as its policy.toml sets `listen = false`: hermes's service cannot start"),
            "{plan}"
        );
        assert!(!plan.contains("listen on TCP for hermes"), "{plan}");
        done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        assert!(
            !lab.engine
                .policy(&lab.name)
                .unwrap()
                .snapshot
                .policy
                .net
                .listen
        );
    }

    #[test]
    fn an_installer_not_served_over_https_is_not_downloaded() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let mut runtime = TestRuntime::new(lab._dir.path(), INSTALLS);
        // Nothing listens here, so a curl that tried would exit 7 (could
        // not connect); it exits 1, unsupported protocol, before trying.
        runtime.url = "http://127.0.0.1:9/install.sh".into();
        let err = lab
            .engine
            .install_runtime_with(&alice(), &lab.name, &runtime, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(
                "could not download http://127.0.0.1:9/install.sh: it is not served over HTTPS"
            ) && text.contains("Update enclos"),
            "{text}"
        );
        assert_eq!(lab.runtime(), None);
        assert!(!lab.allows("chatgpt.com"));
        assert_eq!(lab.engine.policy(&lab.name).unwrap().version.version, 1);
        let installers = lab.engine.layout.sandbox_dir("home").join("installers");
        assert!(std::fs::read_dir(&installers).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("hermes-install")
        }));
        assert!(
            std::fs::read_dir(&installers)
                .unwrap()
                .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
        );
        assert!(!lab.audit().contains("runtime install"), "{}", lab.audit());
    }

    #[test]
    fn any_installer_runs_and_the_audit_names_its_hash() {
        // Whatever version the runtime serves (ADR 0029): the entry names
        // what ran.
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let runtime = TestRuntime::new(lab._dir.path(), INSTALLS);
        let Planned::Done(end) = lab
            .engine
            .install_runtime_with(&alice(), &lab.name, &runtime, Confirm::Yes)
            .unwrap()
        else {
            panic!("a dry run");
        };
        assert!(end.installed, "{end:?}");
        let audit = lab.audit();
        assert!(
            audit.contains(&format!("installer sha256 {}", runtime.sha256)),
            "{audit}"
        );
        // At a path of its own hash, so an install running at the same time
        // with another version cannot replace what this one runs.
        let installers = lab.engine.layout.sandbox_dir("home").join("installers");
        let named = format!("hermes-install-{}.sh", runtime.sha256);
        assert_eq!(
            std::fs::read(installers.join(&named)).unwrap(),
            INSTALLS.as_bytes()
        );
        assert!(
            std::fs::read_dir(&installers)
                .unwrap()
                .all(|e| { !e.unwrap().file_name().to_string_lossy().ends_with(".part") })
        );
    }

    #[test]
    fn an_installer_that_fails_leaves_the_sandbox_as_before() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
        assert!(!end.installed);
        assert_eq!(end.recorded, None);
        assert_eq!(end.end.exit, 3);
        assert_eq!(lab.runtime(), None);
        assert!(!lab.allows("chatgpt.com"));
        // The destinations came and went: two versions, back to the first's content.
        let history = lab.engine.state.policy_history(&lab.name).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(end.policy, 3);
        let audit = lab.audit();
        assert!(audit.contains("runtime install failed"), "{audit}");
        assert!(!audit.contains("runtime installed"), "{audit}");
        assert_eq!(
            lab.summary("runtime install failed"),
            "the installer exited with 3; policy v3 without hermes's destinations"
        );
        // The home file was put in place from inside the sandbox before.
        assert!(lab.home.join("bin/mktemp").is_file());
    }

    #[test]
    fn a_reinstall_that_fails_keeps_the_runtime_and_its_destinations() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let before = lab.engine.policy(&lab.name).unwrap();
        assert_eq!(before.version.version, 2);

        let end = done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
        assert!(!end.installed);
        assert_eq!(end.recorded, Some(RuntimeKind::Hermes));
        assert_eq!(end.end.exit, 3);
        // The sandbox is as before the reinstall: the runtime still
        // recorded, and the same active policy, which allows its endpoints.
        assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
        assert!(lab.allows("chatgpt.com"));
        assert!(lab.allows("github.com"));
        let after = lab.engine.policy(&lab.name).unwrap();
        assert_eq!(end.policy, 2);
        assert_eq!(after.version.version, 2);
        assert_eq!(after.snapshot.id, before.snapshot.id);
        assert_eq!(lab.engine.state.policy_history(&lab.name).unwrap().len(), 2);
        assert_eq!(
            lab.summary("runtime install failed"),
            "the installer exited with 3; hermes still recorded as installed, under policy v2"
        );
    }

    #[test]
    fn a_proxy_a_session_started_writes_where_enclos_logs_reads() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        done(lab.install("#!/bin/sh\nexit 3\n", Confirm::Yes).unwrap());
        let files = lab.engine.log_files(&lab.name).unwrap();
        assert_eq!(files.len(), 1, "{files:?}");
        let text = std::fs::read_to_string(&files[0]).unwrap();
        assert!(text.contains("fake proxy on port "), "{text}");
    }

    #[test]
    fn an_install_records_the_runtime_once_its_installer_exits_0_and_agents_follow() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        assert!(end.installed);
        assert_eq!(end.policy, 2);
        assert_eq!(lab.runtime(), Some(RuntimeKind::Hermes));
        assert!(lab.allows("chatgpt.com") && lab.allows("github.com"));
        let installed = lab.engine.policy(&lab.name).unwrap().snapshot.policy;
        assert!(installed.net.listen, "the gateway may listen (ADR 0028)");
        assert_eq!(
            std::fs::read_to_string(lab.home.join("installed")).unwrap(),
            "installed --non-interactive\n"
        );
        let mode = std::fs::metadata(lab.home.join("bin/mktemp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(lab.audit().contains("runtime installed"), "{}", lab.audit());

        // A second install of the same runtime is allowed, another refused.
        let main: AgentName = "main".parse().unwrap();
        let Planned::DryRun(plan) = lab
            .engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run added");
        };
        assert_eq!(
            plan.changes,
            [
                "run `hermes profile create main --clone-from default` in sandbox home under policy v2",
                "run `hermes -p main config set secrets.command.enabled false` in sandbox home under policy v2",
                "record agent home/main"
            ]
        );
        assert!(!lab.home.join("hermes-calls").exists());

        let added = done(
            lab.engine
                .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.agent.name, main);
        let Added::Created(end) = &added.how else {
            panic!("adopted: {added:?}");
        };
        assert_eq!(end.exit, 0);
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n"
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // Twice is refused before the runtime runs again.
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("already has agent main"), "{err}");
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n"
        );
        // A clone whose copied `secrets.command` cannot be turned off would
        // read the built-in agent's secrets: not recorded, and said how to
        // finish by hand (ADR 0036).
        std::fs::write(lab.home.join("hermes-after-fails"), "").unwrap();
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "other".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::FailedAfter { .. }), "{err}");
        assert!(
            err.to_string().contains(
                "enclos connect home -- hermes -p other config set secrets.command.enabled false"
            ),
            "{err}"
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        std::fs::remove_file(lab.home.join("hermes-after-fails")).unwrap();
        std::fs::write(
            lab.home.join("hermes-calls"),
            "profile create main --clone-from default\n-p main config set secrets.command.enabled false\n",
        )
        .unwrap();
        // A name that is a command on the sandbox's PATH is refused.
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "curl".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("command on the sandbox's PATH"),
            "{err}"
        );
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "hermes".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains(".local/bin/hermes"), "{err}");

        // The runtime failing leaves no record, and says how to recover.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .add_agent(&alice(), &lab.name, "other".parse().unwrap(), Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exit 3") && text.contains("~/.hermes/profiles/other"),
            "{text}"
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);

        // The stub made no profile folder: nothing for Hermes to delete.
        let Planned::DryRun(plan) = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed");
        };
        assert_eq!(
            plan.changes,
            ["remove the record of agent home/main, which Hermes no longer has"]
        );
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        let removed = done(
            lab.engine
                .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(
            removed,
            AgentRemoved::RecordOnly {
                kind: RuntimeKind::Hermes,
                files: "~/.hermes/profiles/main".into(),
                why: FilesKept::RuntimeLacksIt,
            }
        );
        assert!(lab.engine.agents(&lab.name).unwrap().is_empty());
        let err = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("has no agent `main`"), "{err}");
    }

    #[test]
    fn removing_an_agent_runs_the_runtimes_delete_then_removes_the_record() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let profile = |a: &str| {
            let dir = lab.home.join(".hermes/profiles").join(a);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("config.yaml"), "").unwrap();
            dir
        };
        let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
        for a in ["main", "kept", "broken"] {
            profile(a);
            done(
                lab.engine
                    .add_agent(&alice(), &lab.name, a.parse().unwrap(), Confirm::Yes)
                    .unwrap(),
            );
        }
        let main: AgentName = "main".parse().unwrap();

        // It asks first, and the dry run says what would go.
        let err = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        let Planned::DryRun(plan) = lab
            .engine
            .remove_agent(&alice(), &lab.name, &main, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run removed");
        };
        assert_eq!(
            plan.changes,
            ["delete agent home/main and its files, with Hermes's own command"]
        );

        let removed = done(
            lab.engine
                .remove_agent(&alice(), &lab.name, &main, false, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(
            removed,
            AgentRemoved::Deleted {
                kind: RuntimeKind::Hermes
            }
        );
        assert!(
            calls().ends_with("profile delete main --yes\n"),
            "{}",
            calls()
        );
        assert!(!lab.home.join(".hermes/profiles/main").exists());
        let names: Vec<String> = lab
            .engine
            .agents(&lab.name)
            .unwrap()
            .iter()
            .map(|a| a.name.to_string())
            .collect();
        assert_eq!(names, ["broken", "kept"]);
        let audit = lab.audit();
        assert!(audit.contains("agent rm run"), "{audit}");
        assert!(audit.contains("deleted"), "{audit}");

        // Hermes failing leaves the record, and says how it ended.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .remove_agent(
                &alice(),
                &lab.name,
                &"broken".parse().unwrap(),
                false,
                Confirm::Yes,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("exited with 3") && err.contains("its record stays"),
            "{err}"
        );
        std::fs::remove_file(lab.home.join("hermes-fails")).unwrap();

        // Hermes saying it deleted an agent it still lists leaves the record.
        std::fs::write(lab.home.join("hermes-keeps"), "").unwrap();
        let err = lab
            .engine
            .remove_agent(
                &alice(),
                &lab.name,
                &"kept".parse().unwrap(),
                false,
                Confirm::Yes,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("still lists it"), "{err}");
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 2);
    }

    #[test]
    fn an_agent_is_imported_with_the_runtime_s_own_import_and_its_archive_recorded() {
        use sha2::{Digest, Sha256};
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        // Larger than one read of the hashing buffer.
        let bytes: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let archive = lab._dir.path().join("main-20261020.tar.gz");
        std::fs::write(&archive, &bytes).unwrap();
        let sha256 = crate::engine::runtime::hex(&Sha256::digest(&bytes));
        let installers = lab.engine.layout.sandbox_dir("home").join("installers");
        let staged = installers.join(format!("agent-main.{}.tar.gz", std::process::id()));
        let planned = installers.join("agent-main.<pid>.tar.gz");
        let copies = || {
            std::fs::read_dir(&installers)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with("agent-")
                })
                .count()
        };
        let main: AgentName = "main".parse().unwrap();

        // A dry run says what would happen and copies nothing.
        let Planned::DryRun(plan) = lab
            .engine
            .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run imported");
        };
        assert_eq!(
            plan.changes,
            [
                format!(
                    "copy {} (sha256 {sha256} now) to a new file such as {}, beside the home of sandbox home, where the sandbox reads it and cannot write",
                    archive.display(),
                    planned.display()
                ),
                format!(
                    "run `hermes profile import '{}' --name main` in sandbox home under policy v2: Hermes extracts the archive inside the sandbox",
                    planned.display()
                ),
                "record agent home/main as imported from that archive".to_owned(),
            ]
        );
        assert_eq!(copies(), 0);
        assert!(!lab.home.join("hermes-calls").exists());

        // The runtime imports the staged copy inside the sandbox: the bytes
        // it reads are the archive's, and the copy goes once it served. The
        // archive and its hash are audited before the runtime runs, and
        // again with the record.
        let added = done(
            lab.engine
                .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.agent.name, main);
        let Added::Imported {
            end,
            archive: imported,
            copy_left,
        } = &added.how
        else {
            panic!("not imported: {:?}", added.how);
        };
        assert_eq!(end.exit, 0);
        assert_eq!(
            (imported.path.as_path(), imported.sha256.as_str()),
            (archive.as_path(), sha256.as_str())
        );
        assert!(copy_left.is_none());
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            format!(
                "profile import {} --name main\n-p main config set secrets.command.enabled false\n",
                staged.display()
            )
        );
        assert_eq!(
            std::fs::read(lab.home.join("imported-main")).unwrap(),
            bytes
        );
        assert!(!staged.exists());
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // Read afresh each time: the audit log grows below.
        let outcome = |command: &str| {
            lab.engine
                .audit(None)
                .unwrap()
                .iter()
                .filter(|e| e.intent.command == command)
                .map(|e| e.finished.as_ref().unwrap().outcome.message.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            outcome("agent import"),
            [format!(
                "copied {} (sha256 {sha256}) to {}",
                archive.display(),
                staged.display()
            )]
        );
        // The import, then the copied `secrets.command` turned off.
        assert_eq!(outcome("agent import session").len(), 2);
        assert_eq!(
            outcome("agent add"),
            [format!(
                "imported from {} (sha256 {sha256})",
                archive.display()
            )]
        );
        // In that order: the copy is audited before the runtime runs.
        let commands: Vec<String> = lab
            .engine
            .audit(None)
            .unwrap()
            .into_iter()
            .map(|e| e.intent.command)
            .filter(|c| c.starts_with("agent "))
            .collect();
        assert_eq!(
            commands,
            [
                "agent import",
                "agent import session",
                "agent import session",
                "agent add"
            ]
        );

        // Refused before the archive is read: a known name, and a name that
        // is a command on the sandbox's PATH.
        let err = lab
            .engine
            .import_agent(&alice(), &lab.name, main.clone(), &archive, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("already has agent main"), "{err}");
        let missing = lab._dir.path().join("missing.tar.gz");
        let err = lab
            .engine
            .import_agent(
                &alice(),
                &lab.name,
                "curl".parse().unwrap(),
                &missing,
                Confirm::Yes,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("command on the sandbox's PATH"),
            "{err}"
        );

        // An archive that is not a plain file of the user's own is refused.
        let other: AgentName = "other".parse().unwrap();
        let refused = |path: &Path, what: &str| {
            let err = lab
                .engine
                .import_agent(&alice(), &lab.name, other.clone(), path, Confirm::Yes)
                .unwrap_err();
            assert!(err.to_string().contains(what), "{what}: {err}");
        };
        refused(&missing, "missing.tar.gz");
        refused(&missing, "Name an export");
        refused(lab._dir.path(), "is not a file");
        let link = lab._dir.path().join("link.tar.gz");
        std::os::unix::fs::symlink(&archive, &link).unwrap();
        refused(&link, "is a link");
        let inside = lab.home.join("export.tar.gz");
        std::fs::write(&inside, &bytes).unwrap();
        refused(&inside, "under a sandbox's folder");
        // Also through a link in a parent folder, and through `..`: only
        // where the opened file really is counts.
        let linked = lab._dir.path().join("exports");
        std::os::unix::fs::symlink(&lab.home, &linked).unwrap();
        refused(&linked.join("export.tar.gz"), "under a sandbox's folder");
        let sandboxes = lab.engine.layout.sandboxes_dir();
        refused(
            &sandboxes.join("../sandboxes/home/home/export.tar.gz"),
            "under a sandbox's folder",
        );
        assert_eq!(
            std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap(),
            format!(
                "profile import {} --name main\n-p main config set secrets.command.enabled false\n",
                staged.display()
            )
        );

        // A failing import records nothing, leaves no copy, and says how
        // to delete what the runtime may have kept.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let err = lab
            .engine
            .import_agent(&alice(), &lab.name, other.clone(), &archive, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exit 3")
                && text.contains("enclos agent list home")
                && text.contains("hermes profile delete other --yes"),
            "{text}"
        );
        assert_eq!(copies(), 0);
        assert_eq!(lab.engine.agents(&lab.name).unwrap().len(), 1);
        // The copy is audited again, with its hash; no record is.
        let copied = outcome("agent import");
        assert_eq!(copied.len(), 2);
        assert!(
            copied[1].contains(&format!("(sha256 {sha256})")),
            "{copied:?}"
        );
        assert_eq!(outcome("agent add").len(), 1);
    }

    #[test]
    fn an_install_with_unapplied_policy_edits_asks_first() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let file = lab.engine.layout.policy_file("home");
        let edited = std::fs::read_to_string(&file)
            .unwrap()
            .replace("allow_add = []", "allow_add = [\"example.com\"]");
        std::fs::write(&file, edited).unwrap();
        let err = lab.install(INSTALLS, Confirm::Ask).unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        assert!(err.to_string().contains("allow example.com"), "{err}");
        assert_eq!(lab.runtime(), None);
        let Planned::DryRun(plan) = lab.install(INSTALLS, Confirm::DryRun).unwrap() else {
            panic!("a dry run installed");
        };
        assert!(
            plan.changes.iter().any(|c| c == "also allow example.com"),
            "{plan:?}"
        );
        // Said yes: both apply.
        let end = done(lab.install(INSTALLS, Confirm::Yes).unwrap());
        assert!(end.installed);
        assert!(lab.allows("example.com") && lab.allows("chatgpt.com"));
    }

    /// A sandbox with Hermes recorded as its runtime, and a way to make a
    /// Hermes profile in its home as `hermes profile create` would.
    fn with_hermes() -> (TempDir, Engine, SandboxName, impl Fn(&str)) {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    Ok(())
                },
            )
            .unwrap();
        let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
        let make = move |agent: &str| {
            std::fs::create_dir_all(profiles.join(agent)).unwrap();
            std::fs::write(profiles.join(agent).join("config.yaml"), "").unwrap();
        };
        (dir, engine, name, make)
    }

    fn compared(check: AgentCheck) -> AgentDiff {
        match check {
            AgentCheck::Compared(diff) => diff,
            AgentCheck::Unreadable(why) => panic!("unreadable: {why}"),
        }
    }

    fn agent(name: &str) -> AgentName {
        name.parse().unwrap()
    }

    #[test]
    fn an_agent_made_inside_the_sandbox_is_reported_then_adopted() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        make("my_bot");
        let diff = compared(engine.check_agents(&name).unwrap());
        assert_eq!(diff.untracked, [agent("scout")]);
        assert_eq!(diff.untrackable, [RuntimeAgentName::new("my_bot").unwrap()]);
        assert!(diff.missing.is_empty());
        let err = engine
            .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("enclos does not track agent `scout`, which Hermes has"),
            "{err}"
        );
        assert!(
            err.to_string().contains("or remove it with Hermes's own"),
            "{err}"
        );

        // The alias Hermes made for it is on the sandbox's PATH, which does
        // not count as a command the agent would shadow.
        let bin = engine.sandbox_home(&name).join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("scout"), "#!/bin/sh\n").unwrap();
        let audited = engine.audit(None).unwrap().len();
        let Planned::DryRun(plan) = engine
            .add_agent(&alice(), &name, agent("scout"), Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run adopted");
        };
        assert_eq!(
            plan.changes,
            ["record agent home/scout, which Hermes already has in the sandbox"]
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), audited);

        let added = done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(added.how, Added::Adopted);
        assert_eq!(added.agent.name, agent("scout"));
        assert!(
            compared(engine.check_agents(&name).unwrap())
                .untracked
                .is_empty()
        );
        // Adopting runs nothing in the sandbox: one audit entry, the record's,
        // and no session (the fake backend could not have run one anyway).
        let entries = engine.audit(None).unwrap();
        assert_eq!(entries.len(), audited + 1);
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "agent add");
        assert_eq!(last.intent.target.as_deref(), Some("home/scout"));
        let outcome = &last.finished.as_ref().unwrap().outcome;
        assert_eq!(outcome.result, AuditResult::Ok);
        assert_eq!(outcome.message, "adopted");
        assert!(engine.show_sandbox(&name).unwrap().sessions.is_empty());
    }

    #[test]
    fn an_import_is_refused_before_anything_runs_and_a_dry_run_copies_nothing() {
        let (dir, engine, name, make) = with_hermes();
        make("scout");
        let archive = dir.path().join("scout.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        // Refused before anything runs: the fake backend would fail.
        let err = engine
            .import_agent(
                &alice(),
                &name,
                "scout".parse().unwrap(),
                &archive,
                Confirm::Yes,
            )
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("needs a fresh name") && text.contains("enclos agent add home/scout"),
            "{text}"
        );
        let err = engine
            .import_agent(
                &alice(),
                &name,
                "default".parse().unwrap(),
                &archive,
                Confirm::Yes,
            )
            .unwrap_err();
        assert!(err.to_string().contains("built-in agent"), "{err}");
        // A dry run of a fresh name copies nothing and makes no folder.
        let Planned::DryRun(plan) = engine
            .import_agent(
                &alice(),
                &name,
                "fresh".parse().unwrap(),
                &archive,
                Confirm::DryRun,
            )
            .unwrap()
        else {
            panic!("a dry run imported");
        };
        assert!(
            plan.changes[0].starts_with(&format!("copy {} (sha256 ", archive.display())),
            "{plan:?}"
        );
        assert_eq!(
            plan.changes[2],
            "record agent home/fresh as imported from that archive"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(
            !engine
                .layout
                .sandbox_dir("home")
                .join("installers")
                .exists()
        );
    }

    #[test]
    fn an_import_preserves_the_exit_code_when_the_backend_is_unavailable() {
        let (dir, mut engine, name, _make) = with_hermes();
        engine.backends = vec![Box::new(FakeBackend::unavailable(
            BackendKind::Seatbelt,
            "this host cannot run the backend",
        ))];
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::REFUSED, "{err}");
        let text = err.to_string();
        assert!(
            text.contains("this host cannot run the backend")
                && text.contains("did not finish")
                && text.contains("Nothing was recorded")
                && text.contains("enclos agent add home/fresh"),
            "{text}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        let installers = engine.layout.sandbox_dir("home").join("installers");
        assert_eq!(std::fs::read_dir(installers).unwrap().count(), 0);
    }

    #[test]
    fn an_import_whose_session_fails_records_nothing_and_leaves_no_copy() {
        let (dir, engine, name, _make) = with_hermes();
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        // The fake backend cannot start a session: the copy is made and
        // audited, then the session fails.
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("did not finish")
                && text.contains("Nothing was recorded")
                && text.contains("enclos agent add home/fresh"),
            "{text}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        let installers = engine.layout.sandbox_dir("home").join("installers");
        assert_eq!(std::fs::read_dir(&installers).unwrap().count(), 0);
        let entries = engine.audit(None).unwrap();
        let copied: Vec<_> = entries
            .iter()
            .filter(|e| e.intent.command == "agent import")
            .collect();
        assert_eq!(copied.len(), 1);
        let outcome = &copied[0].finished.as_ref().unwrap().outcome;
        assert_eq!(outcome.result, AuditResult::Ok);
        assert!(
            outcome.message.contains(&archive.display().to_string())
                && outcome.message.contains("(sha256 "),
            "{}",
            outcome.message
        );
        assert!(!entries.iter().any(|e| e.intent.command == "agent add"));
    }

    #[test]
    fn an_import_is_refused_when_the_runtimes_agents_cannot_be_read() {
        let (dir, engine, name, _make) = with_hermes();
        // Something in the sandbox replaced ~/.hermes with a link.
        let home = engine.sandbox_home(&name);
        std::os::unix::fs::symlink(dir.path(), home.join(".hermes")).unwrap();
        let archive = dir.path().join("fresh.tar.gz");
        std::fs::write(&archive, b"an export").unwrap();
        let err = engine
            .import_agent(&alice(), &name, agent("fresh"), &archive, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot tell whether agent fresh is already there"),
            "{err}"
        );
        assert!(
            !engine
                .layout
                .sandbox_dir("home")
                .join("installers")
                .exists()
        );
    }

    #[test]
    fn an_agent_deleted_inside_the_sandbox_is_reported_missing() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        make("ranger");
        for a in ["scout", "ranger"] {
            done(
                engine
                    .add_agent(&alice(), &name, agent(a), Confirm::Yes)
                    .unwrap(),
            );
        }
        let profiles = engine.sandbox_home(&name).join(".hermes/profiles");
        // As `hermes profile delete` does: a tombstone, the folder kept.
        std::fs::create_dir_all(profiles.join(".deleted/scout")).unwrap();
        std::fs::remove_dir_all(profiles.join("ranger")).unwrap();
        let diff = compared(engine.check_agents(&name).unwrap());
        assert_eq!(diff.missing, [agent("ranger"), agent("scout")]);
        assert!(diff.untracked.is_empty());
        // Nothing left to delete: removing them takes only the record, and
        // runs nothing in the sandbox (the fake backend would fail).
        for a in ["scout", "ranger"] {
            done(
                engine
                    .remove_agent(&alice(), &name, &agent(a), false, Confirm::Yes)
                    .unwrap(),
            );
        }
        assert!(engine.agents(&name).unwrap().is_empty());
    }

    #[test]
    fn removing_an_agent_with_its_files_asks_first() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        let scout = agent("scout");
        let err = engine
            .remove_agent(&alice(), &name, &scout, false, Confirm::Ask)
            .unwrap_err();
        assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
        let Planned::DryRun(plan) = engine
            .remove_agent(&alice(), &name, &scout, false, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run plans");
        };
        assert_eq!(
            plan.changes,
            ["delete agent home/scout and its files, with Hermes's own command"]
        );
        // `--keep-data` needs no confirmation and leaves the files.
        done(
            engine
                .remove_agent(&alice(), &name, &scout, true, Confirm::Ask)
                .unwrap(),
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert!(
            engine
                .sandbox_home(&name)
                .join(".hermes/profiles/scout")
                .exists()
        );
    }

    #[test]
    fn a_linked_hermes_folder_is_reported_unreadable_and_agent_add_refuses_to_guess() {
        let (_dir, engine, name, make) = with_hermes();
        make("scout");
        done(
            engine
                .add_agent(&alice(), &name, agent("scout"), Confirm::Yes)
                .unwrap(),
        );
        let hermes = engine.sandbox_home(&name).join(".hermes");
        let kept = engine.sandbox_home(&name).join("hermes-kept");
        std::fs::rename(&hermes, &kept).unwrap();
        std::os::unix::fs::symlink(&kept, &hermes).unwrap();
        let AgentCheck::Unreadable(why) = engine.check_agents(&name).unwrap() else {
            panic!("compared through a link");
        };
        assert_eq!(why.to_string(), "~/.hermes is a link");
        let audited = engine.audit(None).unwrap().len();
        let err = engine
            .add_agent(&alice(), &name, agent("ranger"), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot read Hermes's agents in sandbox home (~/.hermes is a link)"),
            "{err}"
        );
        assert_eq!(engine.audit(None).unwrap().len(), audited);
        let err = engine
            .remove_agent(&alice(), &name, &agent("ranger"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("has no agent `ranger`, and enclos cannot read"),
            "{err}"
        );
        // Deleting a tracked agent's files would need the list; the record
        // alone can still go, since it is enclos's.
        let err = engine
            .remove_agent(&alice(), &name, &agent("scout"), false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot read Hermes's agents")
                && err.to_string().contains("--keep-data"),
            "{err}"
        );
        done(
            engine
                .remove_agent(&alice(), &name, &agent("scout"), true, Confirm::Yes)
                .unwrap(),
        );
        assert!(engine.agents(&name).unwrap().is_empty());
    }

    #[test]
    fn the_check_compares_names_both_ways() {
        let tracked = |n: &str| AgentRecord {
            name: n.parse().unwrap(),
            created_at: "2026-01-02T03:04:05Z".parse().unwrap(),
        };
        let names = |names: &[&str]| -> Vec<RuntimeAgentName> {
            names
                .iter()
                .map(|n| RuntimeAgentName::new(n).unwrap())
                .collect()
        };
        let found = names(&["main", "scout", "a"]);
        let diff = AgentDiff::compare(&found, &[tracked("main"), tracked("gone")], None);
        assert_eq!(diff.untracked, [agent("scout")]);
        assert_eq!(diff.untrackable, [RuntimeAgentName::new("a").unwrap()]);
        assert_eq!(diff.missing, [agent("gone")]);
        assert!(!diff.is_clean());
        assert!(AgentDiff::compare(&found[..1], &[tracked("main")], None).is_clean());
        // A runtime that lists its built-in agent: never untracked.
        let both = names(&["main", "default"]);
        let default = crate::runtime::BuiltinAgent::new("default");
        assert!(AgentDiff::compare(&both, &[tracked("main")], Some(default)).is_clean());
    }

    /// An installer whose `hermes gateway run` starts a second process and
    /// waits, writing both pids to `gateway-pids` in the home.
    const GATEWAY: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
exec /bin/sleep 600
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    /// An installer whose `hermes gateway run` starts a second process,
    /// writes both pids to `gateway-pids` in the home, and exits 0 a moment
    /// later, leaving the second running.
    const LEAVES: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
/bin/sleep 600 &
printf '%s\\n%s\\n' $! $$ > \"$HOME/gateway-pids.part\"
mv \"$HOME/gateway-pids.part\" \"$HOME/gateway-pids\"
/bin/sleep 1
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    /// A gateway that exits 75 on USR1, as Hermes's does.
    const RESTARTS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\" \"$HOME/.hermes\"
printf 'model: a\\n' > \"$HOME/.hermes/config.yaml\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
trap 'exit 75' USR1
: > \"$HOME/gateway-up\"
i=0
while [ $i -lt 600 ]; do /bin/sleep 0.1; i=$((i+1)); done
exit 0
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    #[test]
    fn a_service_restarts_once_its_runtime_settings_change() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
        let home = lab.home.clone();
        let edit = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !home.join("gateway-up").exists() {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(30),
                    "no gateway"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
        });
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        edit.join().unwrap();
        assert_eq!(end.exit, 75, "{end:?}");
        assert!(end.restarting, "{end:?}");
        assert_eq!(
            end.notes,
            ["~/.hermes/.env changed: asked the gateway service to restart"],
            "{end:?}"
        );
        let audit = lab.audit();
        assert!(audit.contains("service restart"), "{audit}");
        assert!(open_service_sessions(&lab).is_empty());
    }

    #[test]
    fn a_settings_restart_that_could_not_be_recorded_is_asked_again() {
        use std::os::unix::fs::PermissionsExt;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
        let home = lab.home.clone();
        let audit = lab.engine.layout.audit_log();
        let edit = std::thread::spawn(move || {
            // The gateway runs, and `launch` has recorded it: the audit made
            // read-only fails the restart, not the start's own entry.
            let log = crate::audit::jsonl::JsonlAuditLog::new(&audit);
            let launched = || {
                use crate::audit::AuditLog;
                log.entries(&Default::default())
                    .unwrap()
                    .iter()
                    .any(|e| e.intent.command == "launch" && e.finished.is_some())
            };
            let start = std::time::Instant::now();
            while !home.join("gateway-up").exists() || !launched() {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(30),
                    "no gateway"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let mode = |m| std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(m));
            mode(0o400).unwrap();
            std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
            // The failed attempt comes 5 to 9 s after the write.
            std::thread::sleep(std::time::Duration::from_secs(20));
            mode(0o600).unwrap();
            std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=y\n").unwrap();
        });
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        edit.join().unwrap();
        assert_eq!(end.exit, 75, "{end:?}");
        assert!(end.restarting, "{end:?}");
        assert!(
            end.notes.iter().any(|n| n.starts_with(
                "~/.hermes/.env changed, but the gateway service was not asked to restart"
            )),
            "{end:?}"
        );
        assert!(
            end.notes.contains(
                &"~/.hermes/.env changed: asked the gateway service to restart".to_owned()
            ),
            "{end:?}"
        );
    }

    #[test]
    fn a_restart_is_not_sent_while_a_session_is_recorded_under_the_lock() {
        use std::os::unix::process::CommandExt;
        let lab = Lab::new();
        let sleep = || {
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .unwrap()
        };
        let record = |child: &std::process::Child, kind| crate::model::session::SessionRecord {
            id: crate::model::session::SessionId(0),
            sandbox: lab.name.clone(),
            kind,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: Some(child.id()),
            root: crate::lifecycle::process::reference_of_child(child).unwrap(),
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        // Stands for the service's program: USR1 ends a `sleep`.
        let mut service = sleep();
        let service_session = record(&service, crate::model::session::SessionKind::Service);
        let mut connected = sleep();
        {
            let lock = lab.engine.state.lock().unwrap();
            let sandbox = lab.engine.state.get(&lab.name).unwrap().unwrap();
            let session = record(&connected, crate::model::session::SessionKind::Interactive);
            lab.engine
                .state
                .start_session(&lock, &session, &sandbox)
                .unwrap();
        }
        let env = [crate::runtime::HomePath::new(".hermes/.env").unwrap()];
        let asked = lab
            .engine
            .ask_restart(
                &alice(),
                &service_session,
                crate::runtime::Signal::Usr1,
                &env,
            )
            .unwrap();
        assert_eq!(asked, None);
        std::thread::sleep(Duration::from_millis(200));
        assert!(service.try_wait().unwrap().is_none(), "signalled");
        assert!(!lab.audit().contains("service restart"), "{}", lab.audit());

        connected.kill().unwrap();
        connected.wait().unwrap();
        let asked = answered(|| {
            lab.engine
                .ask_restart(
                    &alice(),
                    &service_session,
                    crate::runtime::Signal::Usr1,
                    &env,
                )
                .unwrap()
        });
        assert_eq!(asked, Some(Ok(())));
        let status = service.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(USR1)
        );
        assert!(lab.audit().contains("service restart"), "{}", lab.audit());
    }

    #[test]
    fn an_exec_session_does_not_hold_back_a_settings_restart() {
        use std::os::unix::process::CommandExt;
        let lab = Lab::new();
        let sleep = || {
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .unwrap()
        };
        let record = |child: &std::process::Child, kind| crate::model::session::SessionRecord {
            id: crate::model::session::SessionId(0),
            sandbox: lab.name.clone(),
            kind,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: Some(child.id()),
            root: crate::lifecycle::process::reference_of_child(child).unwrap(),
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        let mut service = sleep();
        let service_session = record(&service, crate::model::session::SessionKind::Service);
        // A script's command, running: nobody is in a setup or a TUI.
        let mut exec = sleep();
        {
            let lock = lab.engine.state.lock().unwrap();
            let sandbox = lab.engine.state.get(&lab.name).unwrap().unwrap();
            let session = record(&exec, crate::model::session::SessionKind::Exec);
            lab.engine
                .state
                .start_session(&lock, &session, &sandbox)
                .unwrap();
        }
        let env = [crate::runtime::HomePath::new(".hermes/.env").unwrap()];
        let asked = answered(|| {
            lab.engine
                .ask_restart(
                    &alice(),
                    &service_session,
                    crate::runtime::Signal::Usr1,
                    &env,
                )
                .unwrap()
        });
        assert_eq!(asked, Some(Ok(())));
        let status = service.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(USR1)
        );
        exec.kill().unwrap();
        exec.wait().unwrap();
    }

    #[test]
    fn a_settings_restart_waits_until_no_one_is_connected() {
        use std::os::unix::process::CommandExt;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RESTARTS, Confirm::Yes).unwrap()).installed);
        let mut setup = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        {
            let lock = lab.engine.state.lock().unwrap();
            let record = lab.engine.state.get(&lab.name).unwrap().unwrap();
            let session = crate::model::session::SessionRecord {
                id: crate::model::session::SessionId(0),
                sandbox: lab.name.clone(),
                kind: crate::model::session::SessionKind::Interactive,
                service: None,
                version: 1,
                snapshot: crate::model::policy::SnapshotId("s".into()),
                compiled: None,
                pgid: Some(setup.id()),
                root: crate::lifecycle::process::reference_of_child(&setup).unwrap(),
                tracked: Vec::new(),
                started_at: crate::model::now(),
                ended_at: None,
            };
            lab.engine
                .state
                .start_session(&lock, &session, &record)
                .unwrap();
        }
        // Connected for longer than `SETTLE` after the change.
        let home = lab.home.clone();
        let edit = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !home.join("gateway-up").exists() {
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(30),
                    "no gateway"
                );
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            std::fs::write(home.join(".hermes/.env"), "TELEGRAM_BOT_TOKEN=x\n").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(12));
            setup.kill().unwrap();
            setup.wait().unwrap();
            std::time::Instant::now()
        });
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        let returned = std::time::Instant::now();
        let left = edit.join().unwrap();
        assert!(returned > left, "restarted while someone was connected");
        assert_eq!(end.exit, 75, "{end:?}");
        assert!(end.restarting, "{end:?}");
    }

    /// A runtime whose gateway records whether it was launched in enclos's
    /// terminal, and exits.
    const RECORDS_TERMINAL: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${ENCLOS_FAKE_IN_TERMINAL:-unset}\" > \"$HOME/in-terminal\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    fn pids_in(file: &Path) -> Vec<u32> {
        std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|l| l.parse().unwrap())
            .collect()
    }

    fn assert_gone(pids: &[u32]) {
        for pid in pids {
            let running = crate::lifecycle::process::reference(*pid).unwrap();
            assert!(running.is_none(), "pid {pid} still runs");
        }
    }

    fn open_service_sessions(lab: &Lab) -> Vec<crate::model::session::SessionRecord> {
        lab.engine
            .state
            .sessions(&lab.name, true)
            .unwrap()
            .into_iter()
            .filter(|s| s.kind == crate::model::session::SessionKind::Service)
            .collect()
    }

    /// A process the session's program double-forks, in a group of its own
    /// and with no parent, still holds the session's marker (ADR 0030).
    /// With what the session recorded forgotten, so that only the marker
    /// can tell: `show` lists it, `status` counts the session as running,
    /// and `sandbox stop` ends it and removes the marker. Before markers it
    /// was not even seen.
    #[test]
    fn stop_ends_a_process_that_left_its_session_by_a_double_fork() {
        use std::time::{Duration, Instant};

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let escape = "/usr/bin/perl -e 'use POSIX; exit if fork; POSIX::setsid(); exit if fork; \
            open(my $f, \">\", \"$ENV{HOME}/escaped\") or die; print $f $$; close $f; \
            exec(\"/bin/sleep\", \"600\")'; /bin/sleep 1";
        done(
            lab.engine
                .connect(
                    &alice(),
                    &lab.name,
                    vec!["/bin/sh".into(), "-c".into(), escape.into()],
                    Confirm::Yes,
                )
                .unwrap(),
        );
        let file = lab.home.join("escaped");
        let start = Instant::now();
        while !file.exists() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let pid: u32 = std::fs::read_to_string(&file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let escaped = crate::lifecycle::process::reference(pid).unwrap().unwrap();

        let session = lab
            .engine
            .state
            .sessions(&lab.name, true)
            .unwrap()
            .into_iter()
            .find(|s| s.kind == crate::model::session::SessionKind::Interactive)
            .unwrap();
        assert_ne!(
            crate::lifecycle::process::group_of(pid).unwrap(),
            session.pgid,
            "the process did not leave the session's group"
        );
        lab.engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| Ok(lab.engine.state.track(lock, session.id, &[])?),
            )
            .unwrap();
        let view = lab.engine.show_sandbox(&lab.name).unwrap();
        let listed = view
            .sessions
            .iter()
            .any(|v| v.session.id == session.id && v.members.iter().any(|m| m.pid == pid));
        let status = lab.engine.status(Some(&lab.name)).unwrap();
        let gone = status.sandboxes[0].gone_sessions;

        let report = done(
            lab.engine
                .stop_sandbox(&alice(), &lab.name, Confirm::Yes)
                .unwrap(),
        );
        let survived = crate::lifecycle::process::is_same(&escaped).unwrap();
        if survived {
            // The test's own process, checked by pid and start time.
            let _ = crate::lifecycle::process::signal_process(
                &escaped,
                crate::lifecycle::process::Signal::Kill,
            );
        }
        assert!(!survived, "the double-forked process survived the stop");
        assert!(report.survivors.is_empty(), "{:?}", report.survivors);
        assert!(listed, "show did not list the process holding the marker");
        assert_eq!(gone, 0, "status found the session gone");
        let left: Vec<_> = std::fs::read_dir(lab.engine.markers(&lab.name))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "markers left: {left:?}");
    }

    /// A member whose TERM handler forks a child and exits leaves an orphan
    /// that neither its group nor its parent proves the session's. It holds
    /// the marker, so the look after the first stop proves it, and it is
    /// stopped too instead of surviving (ADR 0030).
    #[test]
    fn a_child_forked_while_stopping_is_stopped_through_its_marker() {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        let forked = lab.home.join("forked");
        let script = format!(
            "trap '(/bin/sleep 600 & echo $! > \"{}\") ; exit 0' TERM; while :; do /bin/sleep 0.1; done",
            forked.display()
        );
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let marker = lab.engine.new_marker(&lab.name).unwrap();
        let (mut child, marked) = marker.spawn(&mut command).unwrap();
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        lab.engine.name_marker(&lab.name, marked, &root).unwrap();
        let session = crate::model::session::SessionRecord {
            id: crate::model::session::SessionId(0),
            sandbox: lab.name.clone(),
            kind: crate::model::session::SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: Some(child.id()),
            root,
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };

        let stopped = lab
            .engine
            .stop_marked(
                &session,
                Duration::from_millis(500),
                crate::lifecycle::stop::stop,
            )
            .unwrap();
        let _ = child.wait();
        let start = Instant::now();
        while !forked.exists() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid: u32 = std::fs::read_to_string(&forked)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child_ref = crate::lifecycle::process::reference(pid).unwrap();
        let alive = child_ref.is_some();
        if let Some(child_ref) = child_ref {
            // The test's own child, checked by pid and start time.
            let _ = crate::lifecycle::process::signal_process(
                &child_ref,
                crate::lifecycle::process::Signal::Kill,
            );
        }
        assert!(!alive, "the forked child survived: {stopped:?}");
        assert!(
            matches!(stopped, crate::lifecycle::stop::Stopped::Clean),
            "{stopped:?}"
        );
    }

    /// Two stops of a session together: the first's survivors that still
    /// run and that the second did not report stay reported (ADR 0030).
    #[test]
    fn two_stops_keep_a_survivor_of_the_first_that_still_runs() {
        use crate::lifecycle::stop::{Stopped, Survivor, Why};
        use crate::model::session::Member;

        let survivor = |pid: u32, why: Why| Survivor {
            member: Member {
                pid,
                started: format!("start {pid}"),
                command: "sleep".into(),
            },
            why,
        };
        let runs = |p: &crate::model::session::ProcessRef| Ok(p.pid == 1 || p.pid == 2);
        let merged = |first, second| super::session::merged(first, second, runs).unwrap();
        // One still running that the second stop could not see is kept.
        let first =
            Stopped::Survivors(vec![survivor(1, Why::Survived), survivor(3, Why::Survived)]);
        let Stopped::Survivors(left) = merged(first, Stopped::Clean) else {
            panic!("a survivor of the first stop was dropped");
        };
        assert_eq!(left, [survivor(1, Why::Survived)]);
        // The second's own report wins for one both saw.
        let first = Stopped::Survivors(vec![survivor(2, Why::NotSignalled)]);
        let second = Stopped::Survivors(vec![survivor(2, Why::Survived)]);
        let Stopped::Survivors(left) = merged(first, second) else {
            panic!("no survivor");
        };
        assert_eq!(left, [survivor(2, Why::Survived)]);
        // Gone only when both found nothing; a survivor since gone is not kept.
        assert!(matches!(
            merged(Stopped::Gone, Stopped::Gone),
            Stopped::Gone
        ));
        assert!(matches!(
            merged(Stopped::Clean, Stopped::Gone),
            Stopped::Clean
        ));
        let first = Stopped::Survivors(vec![survivor(3, Why::NotSignalled)]);
        assert!(matches!(merged(first, Stopped::Gone), Stopped::Clean));
        // One only counted that still runs stays reported, never signalled.
        let first = Stopped::Survivors(vec![survivor(1, Why::NotSignalled)]);
        let Stopped::Survivors(left) = merged(first, Stopped::Gone) else {
            panic!("a counted survivor still running was dropped");
        };
        assert_eq!(left, [survivor(1, Why::NotSignalled)]);
    }

    /// A process holding one session's marker is that session's member,
    /// never another's (ADR 0030).
    #[test]
    fn a_marker_holder_is_its_own_sessions_member_only() {
        use crate::lifecycle::marker::name_of;
        use crate::lifecycle::process::Proc;

        let root = |pid: u32| crate::model::session::ProcessRef {
            pid,
            started: format!("start {pid}"),
        };
        let session = |id: i64, pid: u32| crate::model::session::SessionRecord {
            id: crate::model::session::SessionId(id),
            sandbox: "home".parse().unwrap(),
            kind: crate::model::session::SessionKind::Interactive,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            pgid: None,
            root: root(pid),
            tracked: Vec::new(),
            started_at: crate::model::now(),
            ended_at: None,
        };
        let proc_ = |pid: u32| Proc {
            pid,
            ppid: 1,
            pgid: pid,
            started: format!("start {pid}"),
            command: "sleep".into(),
        };
        let (a, b) = (session(1, 10), session(2, 20));
        let held = super::session::Held::from([(
            name_of(&a.root),
            std::collections::BTreeSet::from([11, 12]),
        )]);
        let procs = [proc_(11), proc_(12), proc_(21)];
        let of_a = super::session::marked_in(&a, &a.tracked, &procs, &held);
        assert_eq!(of_a, [root(11), root(12)]);
        assert!(super::session::marked_in(&b, &b.tracked, &procs, &held).is_empty());
        // A holder no longer listed is not added.
        assert_eq!(
            super::session::marked_in(&a, &a.tracked, &procs[..1], &held),
            [root(11)]
        );
    }

    #[test]
    fn a_runtime_service_told_to_end_stops_its_runtime_and_records_the_end() {
        use std::time::{Duration, Instant};

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let _term = crate::engine::service::TERM_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        let pids_file = lab.home.join("gateway-pids");
        // TERM to this process, as the service manager's stop sends it to
        // `enclos launch`, once the runtime runs: `launch` must catch it,
        // not die of it.
        let markers = lab.engine.markers(&lab.name);
        let teller = {
            let pids_file = pids_file.clone();
            let markers = markers.clone();
            std::thread::spawn(move || {
                // The stub gateway runs, and `launch` has named its marker
                // after it.
                let named = || {
                    std::fs::read_dir(&markers).is_ok_and(|mut files| {
                        files.any(|f| {
                            f.is_ok_and(|f| f.file_name().to_string_lossy().starts_with("root-"))
                        })
                    })
                };
                let start = Instant::now();
                while !pids_file.exists() || !named() {
                    assert!(
                        start.elapsed() < Duration::from_secs(30),
                        "the stub gateway did not start"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                // Who holds the service's marker while it runs (ADR 0030),
                // looked at before TERM and checked after the join.
                let held = crate::lifecycle::marker::holders(&markers);
                signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
                held
            })
        };
        let end = lab.engine.launch(&alice(), &lab.name, "gateway").unwrap();
        let held = teller.join().unwrap().unwrap();
        assert_eq!(held.len(), 1, "{held:?}");
        let holders = held.values().next().unwrap();
        for pid in pids_in(&pids_file) {
            assert!(
                holders.contains(&pid),
                "pid {pid} holds no marker: {held:?}"
            );
        }
        assert!(
            !holders.contains(&std::process::id()),
            "launch holds the marker"
        );
        assert_eq!(std::fs::read_dir(&markers).unwrap().count(), 0);
        // TERM ends `sleep` within the first grace period: KILL would show
        // as signal 9, after `STOP_GRACE`.
        assert_eq!(end.signal, Some(15), "{end:?}");
        assert_eq!(end.left, Left::Nothing, "{end:?}");
        assert_gone(&pids_in(&pids_file));
        assert!(open_service_sessions(&lab).is_empty());
        assert!(lab.audit().contains("service end"), "{}", lab.audit());
    }

    #[test]
    fn what_a_runtime_service_leaves_running_is_stopped_when_it_exits() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        // The service manager would start the service again: what this run
        // left would run beside the next.
        assert_eq!(end.left, Left::Nothing, "{end:?}");
        assert_gone(&pids_in(&lab.home.join("gateway-pids")));
        assert!(open_service_sessions(&lab).is_empty());
    }

    #[test]
    fn a_launch_that_succeeds_after_one_that_failed_marks_the_sandbox_running() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
        // As a `launch` that failed leaves it, for the service manager to
        // start it again.
        {
            let lock = lab.engine.state.lock().unwrap();
            let mut record = lab.engine.state.get(&lab.name).unwrap().unwrap();
            record.state = crate::model::sandbox::SandboxState::Failed {
                reason: "launch failed: for the test".into(),
            };
            lab.engine.state.put(&lock, &record).unwrap();
        }
        let ended = std::sync::atomic::AtomicBool::new(false);
        lab.engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        let sessions = lab.engine.state.sessions(&lab.name, false).unwrap();
        assert!(
            sessions
                .iter()
                .any(|s| s.kind == crate::model::session::SessionKind::Service)
        );
        assert_eq!(
            lab.engine.state.get(&lab.name).unwrap().unwrap().state,
            crate::model::sandbox::SandboxState::Running
        );
    }

    #[test]
    fn a_service_is_never_launched_in_enclos_s_terminal() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RECORDS_TERMINAL, Confirm::Yes).unwrap()).installed);
        // Even when `enclos launch` runs in one, as when run by hand: the
        // service outlives that terminal.
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        let seen = std::fs::read_to_string(lab.home.join("in-terminal")).unwrap();
        assert_eq!(seen, "false");
    }

    /// A runtime whose gateway records the service port it was given.
    const RECORDS_SERVICE_PORT: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${ENCLOS_FAKE_SERVICE_PORT:-unset}\" > \"$HOME/gateway-port\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    /// A runtime whose gateway records its open-file limit, and whether a
    /// variable of enclos's own environment reached it.
    const RECORDS_LIMITS: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s %s' \"$(ulimit -Hn)\" \"${CARGO_MANIFEST_DIR:-absent}\" > \"$HOME/gateway-limits\"
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    /// A service and a session start under the policy's limits, and only
    /// the sandbox's variables reach them through the shell that sets them.
    #[test]
    fn a_service_and_a_session_run_under_the_policys_limits() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RECORDS_LIMITS, Confirm::Yes).unwrap()).installed);
        let before = lab.engine.layout.read_policy("home").unwrap();
        let after = format!("{before}\n[resources]\nopen_files = 64\n");
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
            .unwrap();
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        let seen = std::fs::read_to_string(lab.home.join("gateway-limits")).unwrap();
        assert_eq!(seen, "64 absent");
        let records = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s %s' \"$(ulimit -Hn)\" \"${CARGO_MANIFEST_DIR:-absent}\" > \"$HOME/session-limits\"".into(),
        ];
        done(
            lab.engine
                .connect(&alice(), &lab.name, records, Confirm::Yes)
                .unwrap(),
        );
        let seen = std::fs::read_to_string(lab.home.join("session-limits")).unwrap();
        assert_eq!(seen, "64 absent");
    }

    /// A runtime whose gateway records the secret it was given as $TOKEN.
    const RECORDS_TOKEN: &str = "#!/bin/sh
mkdir -p \"$HOME/.local/bin\"
cat > \"$HOME/.local/bin/hermes\" <<'STUB'
#!/bin/sh
[ \"$3\" = gateway ] || exit 0
printf '%s' \"${TOKEN:-unset}\" > \"$HOME/gateway-token\"
cat \"$HERMES_MANAGED_DIR/.env\" > \"$HOME/gateway-env\" 2>&1
STUB
chmod 700 \"$HOME/.local/bin/hermes\"
";

    /// A service and a session read the secrets their policy grants as they
    /// start: Hermes's gateway from the `.env` of a folder only its sandbox
    /// reads, never in its environment, and a session as variables (ADR
    /// 0034). With one missing from the store, neither starts; with the
    /// store locked, the service does not, and the sandbox says why.
    #[test]
    fn a_service_and_a_session_get_the_secrets_their_policy_grants() {
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::{InMemory, SecretStore};
        use std::os::unix::fs::PermissionsExt;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
        let token: SecretRef = "home/token".parse().unwrap();
        let value = SecretValue::new("tok-123:a'b\\c".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        let before = lab.engine.layout.read_policy("home").unwrap();
        let after = format!("{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n");
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
            .unwrap();

        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        let seen = std::fs::read_to_string(lab.home.join("gateway-token")).unwrap();
        assert_eq!(seen, "unset", "the value is in the gateway's environment");
        let file = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
        assert_eq!(file, "TOKEN=\"tok-123:a'b\\\\c\"\n");
        let folder = lab.engine.layout.sandbox_secrets_dir("home");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&folder), 0o700);
        assert_eq!(mode(&folder.join(".env")), 0o600);

        let records = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' \"$TOKEN\" > \"$HOME/session-token\"".into(),
        ];
        done(
            lab.engine
                .connect(&alice(), &lab.name, records.clone(), Confirm::Yes)
                .unwrap(),
        );
        let session = lab.home.join("session-token");
        assert_eq!(std::fs::read_to_string(&session).unwrap(), "tok-123:a'b\\c");
        // A locked store: the gateway is not started, and the sandbox is
        // marked failed, saying why.
        store.1.set(true);
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err();
        assert!(matches!(err.root(), Error::SecretsLocked { .. }), "{err}");
        let record = lab.engine.state.get(&lab.name).unwrap().unwrap();
        assert!(
            matches!(&record.state, crate::model::sandbox::SandboxState::Failed { reason } if reason.contains("locked")),
            "{:?}",
            record.state
        );
        store.1.set(false);
        // Gone once the sandbox stops.
        done(
            lab.engine
                .stop_sandbox(&alice(), &lab.name, Confirm::Yes)
                .unwrap(),
        );
        assert!(!folder.exists());

        store.remove(&token).unwrap();
        std::fs::remove_file(&session).unwrap();
        let err = lab
            .engine
            .connect(&alice(), &lab.name, records, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SecretMissing { .. }), "{err}");
        assert!(!session.exists(), "the session ran");
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err();
        assert!(err.to_string().contains("$TOKEN"), "{err}");

        // The grant taken out, a file an earlier start left (a crash, a
        // logout) goes as the gateway starts again with no secrets.
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join(".env"), "TOKEN=\"stale\"\n").unwrap();
        let now = lab.engine.layout.read_policy("home").unwrap();
        lab.engine
            .policy_edit(&alice(), &lab.name, &now, &before, Confirm::Yes)
            .unwrap();
        // The stub's `cat` of the file then fails: what it found is that.
        lab.engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert!(!folder.exists());
        let found = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
        assert!(!found.contains("stale"), "{found}");
    }

    /// `enclos launch` writes the sandbox's and each agent's secrets files
    /// from the file store as it does from the Keychain (ADR 0034, ADR 0036).
    #[test]
    fn launch_writes_the_secrets_files_from_the_file_store() {
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::file::FileStore;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("secrets.json"));
        let lab = Lab::with_secrets(Box::new(store));
        assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
        for (secret, value) in [("home/token", "tok-1"), ("home/main-bot", "123:bot")] {
            let secret: SecretRef = secret.parse().unwrap();
            let value = SecretValue::new(value.into()).unwrap();
            done(
                lab.engine
                    .secret_set(&alice(), &secret, Some(&value), Confirm::Yes)
                    .unwrap(),
            );
        }
        let before = lab.engine.layout.read_policy("home").unwrap();
        let granted = format!(
            "{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n[secrets.agents.main]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-bot\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &granted, Confirm::Yes)
            .unwrap();
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        assert_eq!(
            std::fs::read_to_string(lab.home.join("gateway-env")).unwrap(),
            "TOKEN=\"tok-1\"\n"
        );
        let file = lab.engine.layout.agent_secrets_file("home", "main");
        assert_eq!(
            std::fs::read_to_string(file).unwrap(),
            "TELEGRAM_BOT_TOKEN=\"123:bot\"\n"
        );
    }

    /// What the policy grants one agent goes to that agent's own file in
    /// the secrets folder, never to the sandbox's `.env` every agent reads,
    /// nor to a session (ADR 0036); it stays granted until the policy takes
    /// it out, and the file goes with the grant.
    #[test]
    fn an_agents_secrets_go_to_a_file_of_its_own_and_to_no_session() {
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::InMemory;
        use std::os::unix::fs::PermissionsExt;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(RECORDS_TOKEN, Confirm::Yes).unwrap()).installed);
        for (secret, value) in [("home/token", "tok-1"), ("home/main-bot", "123:bot")] {
            let secret: SecretRef = secret.parse().unwrap();
            let value = SecretValue::new(value.into()).unwrap();
            done(
                lab.engine
                    .secret_set(&alice(), &secret, Some(&value), Confirm::Yes)
                    .unwrap(),
            );
        }
        let before = lab.engine.layout.read_policy("home").unwrap();
        let granted = format!(
            "{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n[secrets.agents.main]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-bot\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &granted, Confirm::Yes)
            .unwrap();

        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        let every = std::fs::read_to_string(lab.home.join("gateway-env")).unwrap();
        assert_eq!(
            every, "TOKEN=\"tok-1\"\n",
            "an agent's secret reached every agent"
        );
        let file = lab.engine.layout.agent_secrets_file("home", "main");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "TELEGRAM_BOT_TOKEN=\"123:bot\"\n"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A session gets the sandbox's secrets, not an agent's.
        let records = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' \"${TELEGRAM_BOT_TOKEN:-unset}\" > \"$HOME/session-bot\"".into(),
        ];
        done(
            lab.engine
                .connect(&alice(), &lab.name, records, Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(
            std::fs::read_to_string(lab.home.join("session-bot")).unwrap(),
            "unset"
        );

        // Granted to an agent, a secret is not removed, and the refusal
        // names the agent.
        let bot: SecretRef = "home/main-bot".parse().unwrap();
        let err = lab
            .engine
            .secret_rm(&alice(), &bot, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("$TELEGRAM_BOT_TOKEN for agent main"),
            "{err}"
        );

        // The grant taken out, the agent's file goes at the next start; the
        // sandbox's stays.
        let ungranted = format!("{before}\n[secrets]\nenv = {{ TOKEN = \"secret:home/token\" }}\n");
        lab.engine
            .policy_edit(&alice(), &lab.name, &granted, &ungranted, Confirm::Yes)
            .unwrap();
        lab.engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert!(!file.exists());
        assert!(file.with_file_name(".env").exists());

        // A value no secrets file can hold, granted to an agent: refused
        // before anything is written, the sandbox's file kept as it was.
        let bad: SecretRef = "home/main-bot".parse().unwrap();
        let value = SecretValue::new("a${b}".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &bad, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        let env = file.with_file_name(".env");
        std::fs::write(&env, "KEPT=\"1\"\n").unwrap();
        lab.engine
            .policy_edit(&alice(), &lab.name, &ungranted, &granted, Confirm::Yes)
            .unwrap();
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err();
        assert!(
            matches!(err.root(), Error::SecretsFileRefused { .. }),
            "{err}"
        );
        assert!(!file.exists());
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "KEPT=\"1\"\n");
    }

    /// `runtime configure` with settings only: the agent reads its own
    /// secrets, and each setting names a secret only as a `${VAR}` the
    /// policy grants it, never as the secret (ADR 0036).
    #[test]
    fn an_agent_is_given_settings_that_name_its_secrets() {
        use crate::engine::Setting;
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::InMemory;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
        let set = |settings: &[&str]| {
            let settings: Vec<Setting> = settings.iter().map(|s| s.parse().unwrap()).collect();
            lab.engine
                .configure_agent(&alice(), &lab.name, None, None, &settings, Confirm::Yes)
        };
        // Nothing asked: the agent reads its own secrets, and only that.
        let configured = done(set(&[]).unwrap());
        assert_eq!(configured.agent.as_str(), "default");
        assert!(configured.settings.is_empty() && configured.channel.is_none());
        assert_eq!(calls().lines().count(), 3, "{}", calls());
        assert!(calls().contains("-p default config set secrets.command.enabled true"));

        // A secret named by a variable the policy does not grant: refused,
        // saying how to grant it, and nothing runs.
        let runs = calls().lines().count();
        let err = set(&["platforms.discord.token=${DISCORD_BOT_TOKEN}"]).unwrap_err();
        assert!(
            err.to_string()
                .contains("grants agent default no $DISCORD_BOT_TOKEN")
                && err.to_string().contains("[secrets.agents.default]"),
            "{err}"
        );
        // A secret written as itself, where the name says it is one.
        let err = set(&["platforms.discord.token=123:abc"]).unwrap_err();
        assert!(err.to_string().contains("looks like a secret"), "{err}");
        assert_eq!(calls().lines().count(), runs, "{}", calls());

        // Granted to the agent: set as written, the value never in a command.
        let token: SecretRef = "home/discord".parse().unwrap();
        let value = SecretValue::new("999:discord".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        let before = lab.engine.layout.read_policy("home").unwrap();
        let after = format!(
            "{before}\n[secrets.agents.default]\nenv = {{ DISCORD_BOT_TOKEN = \"secret:home/discord\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
            .unwrap();
        let configured = done(
            set(&[
                "platforms.discord.token=${DISCORD_BOT_TOKEN}",
                "DISCORD_ALLOWED_USERS=111",
            ])
            .unwrap(),
        );
        assert_eq!(
            configured.settings,
            ["platforms.discord.token", "DISCORD_ALLOWED_USERS"]
        );
        assert!(
            calls().ends_with(
                "-p default config set platforms.discord.token ${DISCORD_BOT_TOKEN}\n-p default config set DISCORD_ALLOWED_USERS 111\n"
            ),
            "{}",
            calls()
        );
        assert!(!calls().contains("999:discord"));
    }

    /// What the channel tests read of a bot `runtime configure` set up.
    #[derive(Debug)]
    struct Bot {
        agent: crate::runtime::RuntimeAgentName,
        token: String,
        answers: Vec<crate::model::channel::ChannelUser>,
        reachable: bool,
    }

    /// `runtime configure --channel`, with no other setting.
    #[allow(clippy::too_many_arguments)]
    fn configure_channel(
        engine: &Engine,
        by: &crate::model::audit::Actor,
        name: &SandboxName,
        agent: Option<&crate::model::agent::AgentName>,
        channel: crate::model::channel::Channel,
        token: Option<String>,
        answers: &[crate::model::channel::ChannelUser],
        confirm: Confirm,
    ) -> crate::error::Result<Planned<Bot>> {
        let request = crate::engine::ChannelRequest {
            channel,
            token,
            answers: answers.to_vec(),
        };
        Ok(
            match engine.configure_agent(by, name, agent, Some(request), &[], confirm)? {
                Planned::DryRun(plan) => Planned::DryRun(plan),
                Planned::Done(done) => {
                    let bot = done.channel.expect("a channel was asked for");
                    Planned::Done(Bot {
                        agent: done.agent,
                        token: bot.token,
                        answers: bot.answers,
                        reachable: bot.reachable,
                    })
                }
            },
        )
    }

    /// The built-in agent's bot is set up with the runtime's own commands,
    /// once the policy grants it its token (ADR 0036); the value goes into
    /// no command.
    #[test]
    fn a_channel_is_set_up_with_the_runtimes_commands_once_its_token_is_granted() {
        use crate::model::channel::{Channel, ChannelUser};
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::InMemory;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let calls = || std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
        let users: Vec<ChannelUser> = vec!["111".parse().unwrap(), "222".parse().unwrap()];
        let configure = |users: &[ChannelUser], confirm| {
            configure_channel(
                &lab.engine,
                &alice(),
                &lab.name,
                None,
                Channel::Telegram,
                None,
                users,
                confirm,
            )
        };

        let err = configure(&users, Confirm::Yes).unwrap_err();
        assert!(
            err.to_string().contains("enclos secret set home/telegram"),
            "{err}"
        );
        let err = configure(&[], Confirm::Yes).unwrap_err();
        assert!(err.to_string().contains("--allow-user"), "{err}");
        assert!(!calls().contains("config set"), "{}", calls());

        let token: SecretRef = "home/telegram".parse().unwrap();
        let value = SecretValue::new("123:tok".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        let before = lab.engine.layout.read_policy("home").unwrap();
        // Granted to the whole sandbox, it would reach every agent and win
        // over each one's own (ADR 0036): refused, saying where it goes.
        let sandbox_wide = format!(
            "{before}\n[secrets]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n"
        );
        let err = lab
            .engine
            .policy_edit(&alice(), &lab.name, &before, &sandbox_wide, Confirm::Yes)
            .unwrap_err();
        assert!(
            matches!(&err, Error::Policy(e) if e.is_refused())
                && err.to_string().contains("[secrets.agents.default]"),
            "{err}"
        );
        assert!(!calls().contains("config set"), "{}", calls());
        let after = format!(
            "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
            .unwrap();

        // A token Hermes's own setup left in plain text in the home is
        // refused until its line goes, though the policy grants one too.
        let env = lab.home.join(".hermes/.env");
        std::fs::create_dir_all(env.parent().unwrap()).unwrap();
        std::fs::write(
            &env,
            "TELEGRAM_ALLOWED_USERS=1\nTELEGRAM_BOT_TOKEN=999:plain\n",
        )
        .unwrap();
        let err = configure(&users, Confirm::Yes).unwrap_err();
        assert!(
            err.to_string()
                .contains("holds TELEGRAM_BOT_TOKEN in plain text"),
            "{err}"
        );
        assert!(!calls().contains("config set"), "{}", calls());
        std::fs::write(&env, "TELEGRAM_ALLOWED_USERS=1\n").unwrap();

        let Planned::DryRun(plan) = configure(&users, Confirm::DryRun).unwrap() else {
            panic!("a dry run configured the channel");
        };
        assert_eq!(plan.changes.len(), 6, "{plan:?}");
        // The agent reads its own secrets file, then the token by name.
        let file = lab.engine.layout.agent_secrets_file("home", "default");
        assert!(
            plan.changes[0].contains("secrets.command.command")
                && plan.changes[0].contains(&file.display().to_string()),
            "{plan:?}"
        );
        assert!(
            plan.changes[4].contains("platforms.telegram.token '${TELEGRAM_BOT_TOKEN}'"),
            "{plan:?}"
        );
        assert!(!calls().contains("config set"), "{}", calls());

        // Each person once.
        let twice: Vec<ChannelUser> = ["222", "111", "222"]
            .iter()
            .map(|u| u.parse().unwrap())
            .collect();
        let set = done(configure(&twice, Confirm::Yes).unwrap());
        assert_eq!(set.token, "TELEGRAM_BOT_TOKEN");
        assert_eq!(set.answers, users);
        assert!(
            set.reachable,
            "the assistant template reaches the public web"
        );
        assert_eq!(set.agent.as_str(), "default");
        // Its secrets file, then who it answers, the bot turned on last.
        assert!(
            calls().ends_with(&format!(
                "-p default config set secrets.command.command cat '{}'\n-p default config set secrets.command.override_existing true\n-p default config set secrets.command.enabled true\n-p default config set TELEGRAM_ALLOWED_USERS 111,222\n-p default config set platforms.telegram.token ${{TELEGRAM_BOT_TOKEN}}\n-p default config set platforms.telegram.enabled true\n",
                file.display()
            )),
            "{}",
            calls()
        );
        assert!(!calls().contains("123:tok"));
        let configured = |lab: &Lab| {
            lab.engine
                .audit(None)
                .unwrap()
                .iter()
                .filter(|e| e.intent.command == "runtime configure")
                .count()
        };
        assert_eq!(configured(&lab), 6, "{}", lab.audit());

        // A variable of another name: refused while the usual one is
        // granted too, which Hermes would read first.
        let usual = lab.engine.layout.read_policy("home").unwrap();
        let both = usual.replace(
            "TELEGRAM_BOT_TOKEN = ",
            "TELEGRAM_BOT_TOKEN_MAIN = \"secret:home/telegram\", TELEGRAM_BOT_TOKEN = ",
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &usual, &both, Confirm::Yes)
            .unwrap();
        let named = |token: &str| {
            configure_channel(
                &lab.engine,
                &alice(),
                &lab.name,
                None,
                Channel::Telegram,
                Some(token.to_owned()),
                &users,
                Confirm::Yes,
            )
        };
        let runs = calls().lines().count();
        let err = named("TELEGRAM_BOT_TOKEN_MAIN").unwrap_err();
        assert!(
            err.to_string()
                .contains("also gives agent default $TELEGRAM_BOT_TOKEN"),
            "{err}"
        );
        // Granted alone, it sets the bot up; a token Hermes's setup left in
        // the home under the usual name is refused for it too.
        let alone = usual.replace("TELEGRAM_BOT_TOKEN = ", "TELEGRAM_BOT_TOKEN_MAIN = ");
        lab.engine
            .policy_edit(&alice(), &lab.name, &both, &alone, Confirm::Yes)
            .unwrap();
        std::fs::write(&env, "TELEGRAM_BOT_TOKEN=999:plain\n").unwrap();
        let err = named("TELEGRAM_BOT_TOKEN_MAIN").unwrap_err();
        assert!(
            err.to_string()
                .contains("holds TELEGRAM_BOT_TOKEN in plain text"),
            "{err}"
        );
        assert_eq!(calls().lines().count(), runs, "{}", calls());
        std::fs::write(&env, "").unwrap();
        let set = done(named("TELEGRAM_BOT_TOKEN_MAIN").unwrap());
        assert_eq!(set.token, "TELEGRAM_BOT_TOKEN_MAIN");
        assert!(
            calls().contains("${TELEGRAM_BOT_TOKEN_MAIN}"),
            "{}",
            calls()
        );
        for bad in ["1BAD", "A}B", "PATH"] {
            let err = named(bad).unwrap_err();
            assert!(
                err.to_string().contains("cannot hold the bot's token"),
                "{err}"
            );
        }
        lab.engine
            .policy_edit(&alice(), &lab.name, &alone, &usual, Confirm::Yes)
            .unwrap();

        // A command that fails stops the rest, and a later one names what
        // ran before it.
        std::fs::write(lab.home.join("hermes-fails"), "").unwrap();
        let runs = calls().lines().count();
        let err = configure(&users, Confirm::Yes).unwrap_err();
        assert!(err.to_string().contains("exited with 3"), "{err}");
        assert!(!matches!(err, Error::FailedAfter { .. }), "{err}");
        assert_eq!(calls().lines().count(), runs + 1, "{}", calls());
        std::fs::remove_file(lab.home.join("hermes-fails")).unwrap();
        std::fs::write(lab.home.join("hermes-token-fails"), "").unwrap();
        let err = configure(&users, Confirm::Yes).unwrap_err();
        assert!(matches!(err, Error::FailedAfter { .. }), "{err}");
        assert!(err.to_string().contains("TELEGRAM_ALLOWED_USERS"), "{err}");
        assert!(!calls().ends_with("enabled true\n"), "{}", calls());
        std::fs::remove_file(lab.home.join("hermes-token-fails")).unwrap();

        // Under an allowlist that leaves Telegram out: set up, and said.
        let before = lab.engine.layout.read_policy("home").unwrap();
        let after = before.replace("[network]\n", "[network]\nmode = \"allowlist\"\n");
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Yes)
            .unwrap();
        let Planned::DryRun(plan) = configure(&users, Confirm::DryRun).unwrap() else {
            panic!("a dry run configured the channel");
        };
        assert!(
            plan.changes
                .last()
                .unwrap()
                .contains("enclos policy allow home api.telegram.org"),
            "{plan:?}"
        );
        assert!(!done(configure(&users, Confirm::Yes).unwrap()).reachable);
        done(
            lab.engine
                .policy_allow(&alice(), &lab.name, "api.telegram.org", Confirm::Yes)
                .unwrap(),
        );
        assert!(done(configure(&users, Confirm::Yes).unwrap()).reachable);
    }

    /// A token granted only by the pending policy waits for it: nothing
    /// runs before `policy apply`.
    #[test]
    fn a_channel_whose_token_is_only_pending_is_refused() {
        use crate::model::channel::{Channel, ChannelUser};
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::InMemory;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let token: SecretRef = "home/telegram".parse().unwrap();
        let value = SecretValue::new("123:tok".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &token, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        // A session under rules the grant changes keeps it pending.
        let sleeping = super::sandbox::Sleeping::new();
        let mut session = super::sandbox::session_of(&lab.engine, &lab.name, sleeping.process());
        session.compiled = Some("/compiled/at-launch.sb".into());
        super::sandbox::put(&lab.engine, &session);
        let before = lab.engine.layout.read_policy("home").unwrap();
        let after = format!(
            "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/telegram\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &after, Confirm::Ask)
            .unwrap();
        let users: Vec<ChannelUser> = vec!["111".parse().unwrap()];
        let err = configure_channel(
            &lab.engine,
            &alice(),
            &lab.name,
            None,
            Channel::Telegram,
            None,
            &users,
            Confirm::Yes,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("enclos policy apply home"),
            "{err}"
        );
        let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap_or_default();
        assert!(!calls.contains("config set"), "{calls}");
        drop(sleeping);
    }

    /// An agent's own bot (ADR 0036): set up for an agent the sandbox has,
    /// its token granted to that agent alone, and read from that agent's
    /// secrets file; the built-in agent's grant is not that agent's.
    #[test]
    fn an_agent_is_given_a_bot_of_its_own() {
        use crate::model::channel::{Channel, ChannelUser};
        use crate::model::secret::{SecretRef, SecretValue};
        use crate::secrets::InMemory;
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let store = std::rc::Rc::new(InMemory::default());
        let lab = Lab::with_secrets(Box::new(std::rc::Rc::clone(&store)));
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let main: crate::model::agent::AgentName = "main".parse().unwrap();
        let users: Vec<ChannelUser> = vec!["111".parse().unwrap()];
        let configure = |agent: &crate::model::agent::AgentName| {
            configure_channel(
                &lab.engine,
                &alice(),
                &lab.name,
                Some(agent),
                Channel::Telegram,
                None,
                &users,
                Confirm::Yes,
            )
        };
        // Not an agent of the sandbox yet: refused, saying how to add it.
        let err = configure(&main).unwrap_err();
        assert!(
            err.to_string().contains("enclos agent add home/main"),
            "{err}"
        );
        done(
            lab.engine
                .add_agent(&alice(), &lab.name, main.clone(), Confirm::Yes)
                .unwrap(),
        );
        let bot: SecretRef = "home/main-telegram".parse().unwrap();
        let value = SecretValue::new("123:main".into()).unwrap();
        done(
            lab.engine
                .secret_set(&alice(), &bot, Some(&value), Confirm::Yes)
                .unwrap(),
        );
        // Granted to the built-in agent only: not main's, and the message
        // names main's section and a secret of its own.
        let before = lab.engine.layout.read_policy("home").unwrap();
        let to_default = format!(
            "{before}\n[secrets.agents.default]\nenv = {{ TELEGRAM_BOT_TOKEN = \"secret:home/main-telegram\" }}\n"
        );
        lab.engine
            .policy_edit(&alice(), &lab.name, &before, &to_default, Confirm::Yes)
            .unwrap();
        let err = configure(&main).unwrap_err();
        assert!(
            err.to_string()
                .contains("gives agent main no $TELEGRAM_BOT_TOKEN")
                && err.to_string().contains("[secrets.agents.main]")
                && err
                    .to_string()
                    .contains("enclos secret set home/main-telegram"),
            "{err}"
        );
        let to_main = to_default.replace("[secrets.agents.default]", "[secrets.agents.main]");
        lab.engine
            .policy_edit(&alice(), &lab.name, &to_default, &to_main, Confirm::Yes)
            .unwrap();
        let set = done(configure(&main).unwrap());
        assert_eq!(set.agent.as_str(), "main");
        let calls = std::fs::read_to_string(lab.home.join("hermes-calls")).unwrap();
        let file = lab.engine.layout.agent_secrets_file("home", "main");
        assert!(
            calls.contains(&format!(
                "-p main config set secrets.command.command cat '{}'\n",
                file.display()
            )),
            "{calls}"
        );
        assert!(
            calls.ends_with("-p main config set platforms.telegram.enabled true\n"),
            "{calls}"
        );
        assert!(!calls.contains("-p default config set"), "{calls}");
        assert!(!calls.contains("123:main"), "{calls}");
    }

    /// A session is given the port its gateway listens on, and says why when
    /// it is given none; the gateway's own launch is given none (ADR 0028).
    #[test]
    fn a_session_is_given_its_gateways_port_and_the_gateway_none() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(RECORDS_SERVICE_PORT, Confirm::Yes).unwrap()).installed);
        let ended = std::sync::atomic::AtomicBool::new(false);
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert_eq!(end.exit, 0, "{end:?}");
        let seen = std::fs::read_to_string(lab.home.join("gateway-port")).unwrap();
        assert_eq!(seen, "none");

        let records = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s' \"$ENCLOS_FAKE_SERVICE_PORT\" > \"$HOME/session-port\"".into(),
        ];
        let session_port = || std::fs::read_to_string(lab.home.join("session-port")).unwrap();
        // No gateway running: none, and why.
        let end = done(
            lab.engine
                .connect(&alice(), &lab.name, records.clone(), Confirm::Yes)
                .unwrap(),
        );
        assert_eq!(session_port(), "none");
        assert!(
            end.notes
                .iter()
                .any(|n| n.contains("cannot reach the gateway (the gateway is not running)")),
            "{:?}",
            end.notes
        );
        // A gateway listening: its port, and nothing to say.
        let (gateway, port) = super::listener::gateway(&lab.engine, &lab.name, 1);
        let end = lab
            .engine
            .connect(&alice(), &lab.name, records, Confirm::Yes);
        super::listener::end(gateway);
        let end = done(end.unwrap());
        assert_eq!(session_port(), port.to_string());
        assert!(
            !end.notes.iter().any(|n| n.contains("cannot reach")),
            "{:?}",
            end.notes
        );
    }

    #[test]
    fn a_launch_ends_a_service_session_whose_launch_was_killed() {
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(LEAVES, Confirm::Yes).unwrap()).installed);
        // As the service manager's timeout leaves it: a session open, its
        // process gone.
        let dead = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let root = crate::lifecycle::process::reference_of_child(&dead).unwrap();
        let mut dead = dead;
        dead.wait().unwrap();
        record_service_session(&lab, "gateway", root, None);
        assert_eq!(open_service_sessions(&lab).len(), 1);
        let ended = std::sync::atomic::AtomicBool::new(false);
        lab.engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        assert!(open_service_sessions(&lab).is_empty());
    }

    /// Records an open session of the runtime service `service` whose
    /// program is `root`, as a `launch` would have.
    fn record_service_session(
        lab: &Lab,
        service: &str,
        root: crate::model::session::ProcessRef,
        pgid: Option<u32>,
    ) -> crate::model::session::SessionId {
        lab.engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: lab.name.clone(),
                        kind: crate::model::session::SessionKind::Service,
                        service: Some(service.to_owned()),
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid,
                        root,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    Ok(lab.engine.state.put_session(lock, &session)?)
                },
            )
            .unwrap()
    }

    /// A `sleep` this test starts in a process group of its own, standing in
    /// for the runtime of a service whose `launch` was killed: still running,
    /// with nothing waiting for it but this test.
    fn orphan_runtime() -> (std::process::Child, crate::model::session::ProcessRef) {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("600")
            .process_group(0)
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        (child, root)
    }

    /// Waits for the stub gateway to write its pids, runs `then`, then sets
    /// `ended`.
    fn end_once_started(
        pids_file: PathBuf,
        ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
        then: impl FnOnce() + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<u32>> {
        use std::time::{Duration, Instant};
        std::thread::spawn(move || {
            let start = Instant::now();
            while !pids_file.exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "the stub gateway did not start"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            let pids = pids_in(&pids_file);
            then();
            ended.store(true, std::sync::atomic::Ordering::Relaxed);
            pids
        })
    }

    #[test]
    fn a_launch_stops_a_live_session_of_its_service_before_starting_another() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::new();
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        // The gateway a killed `launch` left running, and another service's
        // runtime, which this launch has no reason to touch.
        let (mut prior, prior_root) = orphan_runtime();
        let prior_id = record_service_session(&lab, "gateway", prior_root, Some(prior.id()));
        let (mut other, other_root) = orphan_runtime();
        let other_id = record_service_session(&lab, "mail", other_root, Some(other.id()));

        let ended = Arc::new(AtomicBool::new(false));
        // Whether the prior gateway still ran once the new one started; a
        // zombie, not yet reaped by this test, does not count.
        let prior_pid = prior.id();
        let prior_ran = std::sync::Arc::new(AtomicBool::new(true));
        let teller = {
            let prior_ran = Arc::clone(&prior_ran);
            end_once_started(
                lab.home.join("gateway-pids"),
                Arc::clone(&ended),
                move || {
                    let running = crate::lifecycle::process::reference(prior_pid).unwrap();
                    prior_ran.store(running.is_some(), std::sync::atomic::Ordering::Relaxed);
                },
            )
        };
        let end = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap();
        let started = teller.join().unwrap();

        assert!(
            !prior_ran.load(std::sync::atomic::Ordering::Relaxed),
            "the prior gateway still ran when the new one started"
        );
        prior.wait().unwrap();
        assert_eq!(end.left, Left::Nothing, "{end:?}");
        assert_gone(&started);
        // The other service's session is untouched.
        assert!(
            other.try_wait().unwrap().is_none(),
            "the other service's runtime was ended"
        );
        let open = open_service_sessions(&lab);
        assert_eq!(
            open.iter().map(|s| s.id).collect::<Vec<_>>(),
            [other_id],
            "{open:?}"
        );
        // The launch's audit entry says what it stopped.
        let audit = lab.audit();
        assert!(
            audit.contains(&format!(
                "after stopping and ending gateway service session {prior_id}, left by an earlier launch"
            )),
            "{audit}"
        );
        other.kill().unwrap();
        other.wait().unwrap();
    }

    #[test]
    fn a_runtime_that_outlives_being_told_to_end_is_audited_and_its_session_stays_open() {
        use crate::lifecycle::stop::{Stopped, Survivor, Why};
        use crate::model::audit::AuditResult;
        use crate::model::session::Member;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        // Nothing survives KILL on demand: this stop sends no signal and
        // reports the program as having survived both.
        let lab = Lab::stopping_with(|session, _| {
            Ok(Stopped::Survivors(vec![Survivor {
                member: Member {
                    pid: session.root.pid,
                    started: session.root.started.clone(),
                    command: "hermes".into(),
                },
                why: Why::Survived,
            }]))
        });
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        let ended = Arc::new(AtomicBool::new(false));
        let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err();
        let started = teller.join().unwrap();
        assert!(err.to_string().contains("survived TERM and KILL"), "{err}");

        // The end is audited as failed, naming what still runs.
        let entries = lab.engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "service end");
        let outcome = &last.finished.as_ref().expect("finished").outcome;
        assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
        let open = open_service_sessions(&lab);
        assert_eq!(open.len(), 1, "{open:?}");
        let message = &outcome.message;
        assert!(
            message.contains(&format!("pid {} hermes", open[0].root.pid)),
            "{message}"
        );
        assert!(
            message.contains(&format!("session {} stays open", open[0].id)),
            "{message}"
        );
        assert_eq!(err.to_string(), *message);
        // The session stays open while its program runs; `sandbox stop`,
        // with the real stop, ends it.
        drop(lab);
        assert_gone(&started);
    }

    #[test]
    fn a_runtime_enclos_cannot_stop_is_audited_and_its_session_stays_open() {
        use crate::lifecycle::process::PsError;
        use crate::model::audit::AuditResult;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        // `ps` failing whenever the members are stopped: nothing is signalled.
        let lab = Lab::stopping_with(|_, _| Err(PsError::new("ps failed")));
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        let ended = Arc::new(AtomicBool::new(false));
        let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err();
        let started = teller.join().unwrap();
        assert!(
            err.to_string()
                .contains("could not stop the members of session"),
            "{err}"
        );

        // `launch` returns instead of trying again forever, and the end is
        // audited as failed.
        let entries = lab.engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "service end");
        let outcome = &last.finished.as_ref().expect("finished").outcome;
        assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
        assert!(outcome.message.contains("ps failed"), "{outcome:?}");
        let open = open_service_sessions(&lab);
        assert_eq!(open.len(), 1, "{open:?}");
        drop(lab);
        assert_gone(&started);
    }

    #[test]
    fn a_launch_refuses_to_start_beside_an_earlier_session_that_does_not_stop() {
        use crate::lifecycle::stop::{Stopped, Survivor, Why};
        use crate::model::audit::AuditResult;
        use crate::model::session::Member;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        // The pid of the one runtime this stop reports as surviving KILL,
        // without signalling it; every other session it stops for real.
        static STUBBORN: AtomicU32 = AtomicU32::new(0);
        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let lab = Lab::stopping_with(|session, grace| {
            if session.root.pid != STUBBORN.load(Ordering::Relaxed) {
                return crate::lifecycle::stop::stop(session, grace);
            }
            Ok(Stopped::Survivors(vec![Survivor {
                member: Member {
                    pid: session.root.pid,
                    started: session.root.started.clone(),
                    command: "hermes".into(),
                },
                why: Why::Survived,
            }]))
        });
        assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
        // Two gateways that killed launches left: the first stops, the
        // second does not.
        let (mut first, first_root) = orphan_runtime();
        let first_id = record_service_session(&lab, "gateway", first_root, Some(first.id()));
        let (mut stubborn, stubborn_root) = orphan_runtime();
        STUBBORN.store(stubborn.id(), Ordering::Relaxed);
        let stubborn_id =
            record_service_session(&lab, "gateway", stubborn_root, Some(stubborn.id()));

        let ended = AtomicBool::new(false);
        let err = lab
            .engine
            .launch_until(&alice(), &lab.name, "gateway", &ended)
            .unwrap_err()
            .to_string();
        // It names the process to end, and the session it already ended.
        assert!(
            err.contains(&format!(
                "the gateway service session {stubborn_id} of sandbox {} did not stop (pid {} hermes: still runs after TERM and KILL)",
                lab.name,
                stubborn.id()
            )),
            "{err}"
        );
        assert!(err.contains("a second gateway was not started"), "{err}");
        assert!(err.contains("End what still runs"), "{err}");
        assert!(
            err.contains(&format!(
                "after stopping and ending gateway service session {first_id}, left by an earlier launch"
            )),
            "{err}"
        );

        // No gateway started; the first is stopped and its session ended;
        // the stubborn one's session stays open.
        assert!(!lab.home.join("gateway-pids").exists());
        assert!(
            first.try_wait().unwrap().is_some(),
            "the first gateway runs"
        );
        let open = open_service_sessions(&lab);
        assert_eq!(
            open.iter().map(|s| s.id).collect::<Vec<_>>(),
            [stubborn_id],
            "{open:?}"
        );
        // The failed launch entry says all of it.
        let entries = lab.engine.audit(None).unwrap();
        let last = entries.last().unwrap();
        assert_eq!(last.intent.command, "launch");
        let outcome = &last.finished.as_ref().expect("finished").outcome;
        assert_eq!(outcome.result, AuditResult::Failed, "{outcome:?}");
        assert_eq!(outcome.message, err);
        // `sandbox stop`, with the real stop, ends the stubborn runtime.
        drop(lab);
        stubborn.wait().unwrap();
    }

    #[test]
    fn a_start_ends_the_proxy_a_connect_started_and_leaves_other_sessions() {
        use crate::model::session::SessionKind;
        use crate::service::fake::FakeServices;

        let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
        let fake = std::rc::Rc::new(FakeServices::default());
        let lab = Lab::with_services(Some(Box::new(std::rc::Rc::clone(&fake))));
        // The install starts a proxy as `connect` would, and records it.
        assert!(done(lab.install(INSTALLS, Confirm::Yes).unwrap()).installed);
        let sessions = lab.engine.state.sessions(&lab.name, true).unwrap();
        let proxy = sessions
            .iter()
            .find(|s| s.kind == SessionKind::Proxy)
            .expect("the install recorded a proxy")
            .clone();
        // Another session, which `start` has no reason to end.
        let mut other = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference_of_child(&other).unwrap();
        lab.engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = lab.engine.state.active_policy(&lab.name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: lab.name.clone(),
                        kind: SessionKind::Interactive,
                        service: None,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    lab.engine.state.put_session(lock, &session)?;
                    Ok(())
                },
            )
            .unwrap();

        lab.engine.start_sandbox(&alice(), &lab.name).unwrap();
        assert_eq!(fake.started.borrow().len(), 2);
        assert_gone(&[proxy.root.pid]);
        let open = lab.engine.state.sessions(&lab.name, true).unwrap();
        assert!(
            open.iter().all(|s| s.kind != SessionKind::Proxy),
            "{open:?}"
        );
        assert_eq!(
            open.iter()
                .filter(|s| s.kind == SessionKind::Interactive)
                .count(),
            1
        );
        assert!(
            other.try_wait().unwrap().is_none(),
            "the other session's program was ended"
        );
        other.kill().unwrap();
        other.wait().unwrap();
    }
}

mod services {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use super::*;
    use crate::audit::{AuditError, AuditTicket};
    use crate::engine::ServiceWait;
    use crate::engine::listener::ServiceTimes;
    use crate::engine::service::Unit;
    use crate::model::audit::{AuditEntry, AuditFilter, Intent, VerifyReport};
    use crate::model::plan::Planned;
    use crate::model::runtime::RuntimeKind;
    use crate::model::sandbox::SandboxState;
    use crate::model::session::SessionKind;
    use crate::runtime::ServiceName;
    use crate::service::fake::FakeServices;
    use crate::service::{ServiceLabel, ServiceStatus};
    use crate::state::{StateError, StateLock};

    const GATEWAY: ServiceName = ServiceName::new("gateway");

    pub(super) fn sandbox_with_services(
        runtime: Option<RuntimeKind>,
    ) -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
        let fake = Rc::new(FakeServices::default());
        let (dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
            BackendKind::Seatbelt,
        ))]);
        let engine = engine.with_services(Box::new(Rc::clone(&fake)));
        done(engine.init(&alice(), Confirm::Yes).unwrap());
        let name: SandboxName = "home".parse().unwrap();
        let spec = crate::engine::SandboxSpec {
            name: name.clone(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        if runtime.is_some() {
            engine
                .write(
                    &alice(),
                    "test",
                    None,
                    |_| String::new(),
                    |lock| {
                        let mut record = engine.state.get(&name)?.unwrap();
                        record.runtime = runtime;
                        engine.state.put(lock, &record)?;
                        Ok(())
                    },
                )
                .unwrap();
        }
        (dir, engine, fake, name)
    }

    fn state_of(engine: &Engine, name: &SandboxName) -> SandboxState {
        engine.state.get(name).unwrap().unwrap().state
    }

    /// `connect`'s wait, in milliseconds rather than a minute.
    const QUICK: ServiceTimes = ServiceTimes {
        start: Duration::from_millis(600),
        gone: Duration::from_millis(200),
        poll: Duration::from_millis(20),
    };

    /// A Hermes sandbox whose runtime's files are there.
    pub(super) fn hermes_with_services() -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
        let (dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        (dir, engine, fake, name)
    }

    fn wait_for_gateway(engine: &Engine, name: &SandboxName) -> (ServiceWait, Vec<String>) {
        let mut said = Vec::new();
        let waited = engine
            .start_listener_service_in(&alice(), name, &mut |what| said.push(what), QUICK)
            .unwrap()
            .expect("a gateway to wait for");
        (waited, said)
    }

    fn dry_run(engine: &Engine, name: &SandboxName) -> Vec<String> {
        let planned = engine
            .connect(&alice(), name, Vec::new(), Confirm::DryRun)
            .unwrap();
        let Planned::DryRun(plan) = planned else {
            panic!("a dry run ran");
        };
        plan.changes
    }

    /// Nothing of the sandbox installed: `connect` installs its services,
    /// says so before it waits, and gives up early when no gateway session
    /// opens, connecting anyway (ADR 0028).
    #[test]
    fn connect_starts_the_services_when_none_are_installed() {
        let (_dir, engine, _fake, name) = hermes_with_services();
        let plan = dry_run(&engine, &name);
        assert!(
            plan.iter()
                .any(|c| c.starts_with("start the services of sandbox home")),
            "{plan:?}"
        );
        // The proxy is the services' to start.
        assert!(
            !plan.iter().any(|c| c.contains("start the proxy")),
            "{plan:?}"
        );

        let begun = std::time::Instant::now();
        let (waited, said) = wait_for_gateway(&engine, &name);
        assert!(waited.started, "{waited:?}");
        assert_eq!(waited.late.as_deref(), Some("the gateway is not running"));
        // Given up at `gone`, not `start`.
        assert!(begun.elapsed() < QUICK.start, "{:?}", begun.elapsed());
        assert!(
            said[0].starts_with("starting the services of sandbox home"),
            "{said:?}"
        );
        assert!(said[0].contains("at each login until `enclos sandbox stop home`"));
        assert_eq!(
            said[1],
            "waiting for the gateway of sandbox home to listen…"
        );
        let started = labels_of(&engine.service_status(&name).unwrap());
        assert!(
            started.iter().any(|l| l.ends_with(".gateway")),
            "{started:?}"
        );
    }

    /// Installed already, the services are the service manager's to start
    /// again: `connect` waits, and installs nothing, which would stop the
    /// proxy open sessions use.
    #[test]
    fn connect_waits_for_installed_services_and_starts_nothing() {
        let (_dir, engine, fake, name) = hermes_with_services();
        engine.start_sandbox(&alice(), &name).unwrap();
        let installed = fake.started.borrow().len();
        let stopped = fake.stopped.borrow().len();
        assert_eq!(
            dry_run(&engine, &name),
            [
                "wait for the gateway of sandbox home to listen".to_owned(),
                format!("run `{}` in sandbox home under policy v1", default_shell())
            ]
        );
        let (waited, said) = wait_for_gateway(&engine, &name);
        assert!(!waited.started, "{waited:?}");
        assert_eq!(waited.late.as_deref(), Some("the gateway is not running"));
        assert_eq!(said, ["waiting for the gateway of sandbox home to listen…"]);
        assert_eq!(fake.started.borrow().len(), installed);
        assert_eq!(fake.stopped.borrow().len(), stopped);
    }

    /// A limit no program could start under refuses the start before any
    /// service is removed or installed.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_start_under_a_limit_no_program_could_run_under_installs_nothing() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        let most = crate::backend::max_files_per_process().unwrap();
        if most >= 1 << 20 {
            return;
        }
        let before = engine.layout.read_policy(name.as_str()).unwrap();
        let after = format!("{before}\n[resources]\nopen_files = {}\n", most + 1);
        // Refused as the policy is stored.
        let err = engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.exit_code() == 2 && err.to_string().contains("kern.maxfilesperproc"),
            "{err}"
        );
        // And at start, for one stored past that, as by another build or on
        // a host whose ceiling was higher.
        let id = engine.policy(&name).unwrap().snapshot.id;
        let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
        conn.execute(
            "UPDATE policy_snapshots SET policy = json_set(policy, '$.resources.open_files', ?1) WHERE id = ?2",
            rusqlite::params![(most + 1) as i64, id.0],
        )
        .unwrap();
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("kern.maxfilesperproc"), "{err}");
        assert!(fake.started.borrow().is_empty());
        assert!(fake.stopped.borrow().is_empty());
    }

    /// A sandbox started before its runtime was installed: its proxy
    /// service and no gateway service.
    fn only_the_proxy_installed() -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
        let (dir, engine, fake, name) = sandbox_with_services(None);
        engine.start_sandbox(&alice(), &name).unwrap();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    Ok(engine.state.put(lock, &record)?)
                },
            )
            .unwrap();
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let installed = labels_of(&engine.service_status(&name).unwrap());
        assert!(
            installed.iter().any(|l| l.ends_with(".proxy"))
                && !installed.iter().any(|l| l.ends_with(".gateway")),
            "{installed:?}"
        );
        (dir, engine, fake, name)
    }

    /// A sleep stands in for the proxy service's job, recorded as the
    /// sandbox's running proxy; stopping the service ends it.
    fn proxy_service_running(engine: &Engine, fake: &FakeServices, name: &SandboxName) {
        let label = engine.label(name, Unit::Proxy).unwrap();
        let job = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference(job.id())
            .unwrap()
            .unwrap();
        fake.jobs.borrow_mut().push((label, job));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = engine.state.active_policy(name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Proxy,
                        service: None,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root: root.clone(),
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    Ok(engine.state.put_session(lock, &session)?)
                },
            )
            .unwrap();
    }

    /// Nothing would ever start the gateway of a sandbox with only its proxy
    /// service, so `connect` starts the services, says beforehand that its
    /// running proxy starts again and cuts the open sessions' connections,
    /// and installs the gateway's service.
    #[test]
    fn connect_starts_the_services_when_only_the_proxy_is_installed() {
        let (_dir, engine, fake, name) = only_the_proxy_installed();
        proxy_service_running(&engine, &fake, &name);

        let plan = dry_run(&engine, &name);
        assert!(
            plan[0].starts_with("start the services of sandbox home"),
            "{plan:?}"
        );
        assert!(
            plan[1].contains("cuts the connections of its open sessions"),
            "{plan:?}"
        );
        let (waited, said) = wait_for_gateway(&engine, &name);
        assert!(waited.started, "{waited:?}");
        assert!(
            said[0].starts_with("starting the services of sandbox home")
                && said[0].contains("the connections of its open sessions are cut"),
            "{said:?}"
        );
        let proxy = engine.label(&name, Unit::Proxy).unwrap();
        assert!(fake.stopped.borrow().contains(&proxy));
        let installed = labels_of(&engine.service_status(&name).unwrap());
        assert!(
            installed.iter().any(|l| l.ends_with(".gateway")),
            "{installed:?}"
        );
        assert!(
            fake.started
                .borrow()
                .iter()
                .any(|u| u.label.as_str().ends_with(".gateway"))
        );
    }

    /// A start that fails before the proxy service is removed says nothing
    /// of it: it is still there.
    #[test]
    fn a_failed_start_that_kept_the_proxy_service_does_not_say_it_is_gone() {
        let (_dir, engine, fake, name) = only_the_proxy_installed();
        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        let (waited, _) = wait_for_gateway(&engine, &name);
        assert!(!waited.started, "{waited:?}");
        let late = waited.late.unwrap();
        assert!(late.starts_with("its services could not start:"), "{late}");
        assert!(!late.contains("proxy service was removed"), "{late}");
        let installed = labels_of(&engine.service_status(&name).unwrap());
        assert!(
            installed.iter().any(|l| l.ends_with(".proxy")),
            "{installed:?}"
        );
    }

    /// A start that fails removes every service it replaced: the session is
    /// told that the proxy service is gone too, and how to get it back.
    #[test]
    fn a_failed_start_says_the_proxy_service_it_replaced_is_gone() {
        let (_dir, engine, fake, name) = only_the_proxy_installed();
        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
        let (waited, _) = wait_for_gateway(&engine, &name);
        assert!(!waited.started, "{waited:?}");
        let late = waited.late.unwrap();
        assert!(late.starts_with("its services could not start:"), "{late}");
        assert!(
            late.contains("its proxy service was removed with them")
                && late.contains("`enclos sandbox start home`"),
            "{late}"
        );
        assert!(
            labels_of(&engine.service_status(&name).unwrap()).is_empty(),
            "the proxy service is still installed"
        );
    }

    /// A start that fails is no reason not to connect: it is said, and the
    /// session goes ahead.
    #[test]
    fn a_failed_start_is_a_note_not_an_error() {
        let (_dir, engine, fake, name) = hermes_with_services();
        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
        let (waited, _) = wait_for_gateway(&engine, &name);
        assert!(!waited.started, "{waited:?}");
        let late = waited.late.unwrap();
        assert!(late.starts_with("its services could not start:"), "{late}");
        assert!(late.contains("refused"), "{late}");
    }

    #[test]
    fn connect_starts_nothing_for_a_runtime_whose_files_are_gone() {
        // Recorded, but `.hermes/hermes-agent` is not in the home: its
        // gateway could not run, so nothing is started or waited for.
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let got = engine.start_listener_service_in(&alice(), &name, &mut |_| {}, QUICK);
        assert_eq!(got.unwrap(), None);
        assert!(fake.started.borrow().is_empty());
        assert!(
            !dry_run(&engine, &name)
                .iter()
                .any(|c| c.contains("gateway"))
        );
    }

    /// Whether the runtime is there cannot be told: nothing is started, and
    /// the session is told why.
    #[test]
    fn connect_starts_nothing_when_the_runtimes_files_cannot_be_read() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes")).unwrap();
        std::os::unix::fs::symlink("/tmp", home.join(".hermes/hermes-agent")).unwrap();
        let (waited, said) = wait_for_gateway(&engine, &name);
        assert!(!waited.started && said.is_empty(), "{waited:?} {said:?}");
        let late = waited.late.unwrap();
        assert!(
            late.starts_with("whether hermes is installed cannot be told"),
            "{late}"
        );
        assert!(fake.started.borrow().is_empty());
        let plan = dry_run(&engine, &name);
        assert!(
            plan[0].starts_with("leave the gateway of sandbox home as it is, since whether hermes"),
            "{plan:?}"
        );
    }

    fn labels_of(status: &[(ServiceLabel, ServiceStatus)]) -> Vec<String> {
        status.iter().map(|(l, _)| l.to_string()).collect()
    }

    /// A gateway whose session is open but which binds its listener only a
    /// second later, as one still starting: a `connect` then waits for it,
    /// and never starts the services again, which would stop it (ADR 0028).
    #[test]
    fn connect_waits_for_a_gateway_still_starting_and_starts_nothing() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let mut gateway = std::process::Command::new("/usr/bin/perl")
            .args([
                "-MSocket",
                "-e",
                "sleep 1; socket(my $s, PF_INET, SOCK_STREAM, 0) or die; bind($s, sockaddr_in(0, INADDR_LOOPBACK)) or die; listen($s, 1) or die; sleep 30",
            ])
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference_of_child(&gateway).unwrap();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let record = engine.state.get(&name)?.unwrap();
                    let session = SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Service,
                        service: Some(GATEWAY.as_str().to_owned()),
                        version: 1,
                        snapshot: engine.policy(&name)?.snapshot.id,
                        compiled: None,
                        root,
                        pgid: None,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    engine.state.start_session(lock, &session, &record)?;
                    Ok(())
                },
            )
            .unwrap();
        let waited = engine.start_listener_service(&alice(), &name, &mut |_| {});
        let _ = gateway.kill();
        let _ = gateway.wait();
        let waited = waited.unwrap().expect("it listened only after the look");
        assert!(!waited.started, "{waited:?}");
        assert_eq!(waited.late, None);
        assert!(fake.started.borrow().is_empty());
        assert!(fake.stopped.borrow().is_empty());
    }

    #[test]
    fn a_sandbox_without_a_runtime_starts_only_its_proxy() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        assert_eq!(labels, [engine.label(&name, Unit::Proxy).unwrap()]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        let unit = &fake.started.borrow()[0];
        let args: Vec<_> = unit
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[..4], ["proxy", "run", "home", "--record"]);
        let port = engine.show_sandbox(&name).unwrap().record.proxy_port;
        assert!(args.contains(&port.to_string()), "{args:?}");
        assert!(unit.env.iter().any(|(k, _)| k == "ENCLOS_HOME"));
        assert!(unit.log.ends_with("sandboxes/home/logs/proxy.log"));
        assert_eq!(unit.stop_timeout, crate::engine::service::STOP_TIMEOUT);
    }

    #[test]
    fn hermes_adds_one_gateway_for_the_whole_sandbox_and_stop_removes_both() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        let (proxy_label, gateway_label) = (
            engine.label(&name, Unit::Proxy).unwrap(),
            engine.label(&name, Unit::Runtime(GATEWAY)).unwrap(),
        );
        assert!(
            gateway_label.as_str().ends_with(".home.gateway"),
            "{gateway_label}"
        );
        assert_eq!(labels, [proxy_label.clone(), gateway_label.clone()]);
        assert_eq!(engine.service_labels(&name).unwrap(), labels);
        let gateway = fake.started.borrow()[1].clone();
        assert_eq!(
            gateway.args,
            ["launch", "home", "gateway"].map(std::ffi::OsString::from)
        );
        assert!(gateway.log.ends_with("sandboxes/home/logs/gateway.log"));
        assert_eq!(
            engine.service_status(&name).unwrap(),
            [
                (gateway_label.clone(), ServiceStatus::Loaded),
                (proxy_label.clone(), ServiceStatus::Loaded)
            ]
        );

        let Planned::DryRun(plan) = engine
            .stop_sandbox(&alice(), &name, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run stopped the sandbox");
        };
        assert!(
            plan.changes
                .contains(&format!("stop service {gateway_label}")),
            "{plan:?}"
        );
        assert_eq!(fake.started.borrow().len(), 2);
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(
            report.services,
            [gateway_label.clone(), proxy_label.clone()]
        );
        assert!(fake.started.borrow().is_empty());
        // The gateway first, so it never runs without its proxy.
        assert_eq!(*fake.stopped.borrow(), [gateway_label, proxy_label]);
        assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
    }

    #[test]
    fn services_run_with_the_layout_of_the_enclos_that_started_them() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        engine.start_sandbox(&alice(), &name).unwrap();
        for unit in fake.started.borrow().iter() {
            // That alone: never the comparison baseline (ADR 0006).
            assert_eq!(unit.env, engine.layout.env(), "{}", unit.label);
            assert!(
                unit.env
                    .iter()
                    .all(|(k, _)| k != crate::backend::seatbelt::BASELINE_VAR)
            );
        }
    }

    /// The keychain file `ENCLOS_KEYCHAIN` named reaches the services, which
    /// read their secrets from it: their value, never.
    #[test]
    fn services_reach_the_keychain_of_the_enclos_that_started_them() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let engine = engine.with_secrets(Box::new(crate::secrets::keychain::Keychain::new(
            "enclos.test".into(),
            Some("/Users/alice/test.keychain-db".into()),
        )));
        engine.start_sandbox(&alice(), &name).unwrap();
        let mut expected = engine.layout.env();
        expected.push((
            "ENCLOS_KEYCHAIN".to_owned(),
            "/Users/alice/test.keychain-db".to_owned(),
        ));
        for unit in fake.started.borrow().iter() {
            assert_eq!(unit.env, expected, "{}", unit.label);
        }
    }

    #[test]
    fn starting_again_replaces_the_services_and_a_failed_start_leaves_none() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        engine.start_sandbox(&alice(), &name).unwrap();
        // The earlier ones were removed first, so their processes end.
        assert_eq!(
            *fake.stopped.borrow(),
            [labels[1].clone(), labels[0].clone()]
        );
        assert_eq!(fake.started.borrow().len(), 2);

        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(matches!(err, Error::Service(_)), "{err:?}");
        assert!(err.to_string().contains("refused"), "{err}");
        assert!(
            fake.started.borrow().is_empty(),
            "the proxy stayed installed"
        );
        assert!(engine.service_status(&name).unwrap().is_empty());
        assert!(
            matches!(state_of(&engine, &name), SandboxState::Failed { ref reason } if reason.contains("refused")),
            "{:?}",
            state_of(&engine, &name)
        );
        assert!(
            engine
                .audit(None)
                .unwrap()
                .last()
                .unwrap()
                .finished
                .is_some()
        );

        // When the rollback fails too, both are said.
        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        let Error::CleanupFailed { error, left } = err else {
            panic!("{err:?}");
        };
        assert!(error.to_string().contains("refused"), "{error}");
        assert!(left.contains("would not stop"), "{left}");
    }

    /// The command, result and message of each audit entry from index
    /// `from` on; panics on an entry left open or about another target.
    fn entries_after(engine: &Engine, from: usize) -> Vec<(String, AuditResult, String)> {
        engine.audit(None).unwrap()[from..]
            .iter()
            .map(|e| {
                assert_eq!(e.intent.target.as_deref(), Some("home"), "{e:?}");
                let outcome = &e.finished.as_ref().expect("a closed entry").outcome;
                (
                    e.intent.command.clone(),
                    outcome.result,
                    outcome.message.clone(),
                )
            })
            .collect()
    }

    /// The audit log, except that entries of the commands listed in
    /// `refused` cannot be opened, as when the disk is full.
    struct RefusingAudit {
        inner: JsonlAuditLog,
        refused: Rc<RefCell<Vec<&'static str>>>,
    }

    impl AuditLog for RefusingAudit {
        fn begin<'l>(
            &self,
            lock: &'l StateLock,
            intent: Intent,
        ) -> crate::audit::Result<AuditTicket<'l>> {
            if self.refused.borrow().contains(&intent.command.as_str()) {
                return Err(AuditError::Io {
                    path: "audit.jsonl".into(),
                    source: std::io::Error::other("disk full"),
                });
            }
            self.inner.begin(lock, intent)
        }

        fn finish(&self, ticket: AuditTicket<'_>, outcome: Outcome) -> crate::audit::Result<()> {
            self.inner.finish(ticket, outcome)
        }

        fn entries(&self, filter: &AuditFilter) -> crate::audit::Result<Vec<AuditEntry>> {
            self.inner.entries(filter)
        }

        fn verify(&self) -> crate::audit::Result<VerifyReport> {
            self.inner.verify()
        }

        fn check(&self) -> crate::audit::Result<()> {
            self.inner.check()
        }
    }

    /// Gives the engine an audit log that refuses the commands in the list
    /// returned, empty at first.
    fn refusing_audit(engine: &mut Engine) -> Rc<RefCell<Vec<&'static str>>> {
        let refused = Rc::default();
        engine.audit = Box::new(RefusingAudit {
            inner: JsonlAuditLog::new(engine.layout.audit_log()),
            refused: Rc::clone(&refused),
        });
        refused
    }

    #[test]
    fn a_restart_and_a_stop_record_their_removals_in_order() {
        let (_dir, engine, _fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let [proxy, gateway] =
            [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
        engine.start_sandbox(&alice(), &name).unwrap();

        let from = engine.audit(None).unwrap().len();
        engine.start_sandbox(&alice(), &name).unwrap();
        assert_eq!(
            entries_after(&engine, from),
            [
                (
                    "services remove".to_owned(),
                    AuditResult::Ok,
                    format!("removing {gateway}, {proxy} before sandbox start")
                ),
                (
                    "services removed".to_owned(),
                    AuditResult::Ok,
                    format!("removed {gateway}, {proxy}")
                ),
                (
                    "sandbox start".to_owned(),
                    AuditResult::Ok,
                    format!("{proxy}, {gateway}")
                ),
            ]
        );

        let from = engine.audit(None).unwrap().len();
        done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert_eq!(
            entries_after(&engine, from),
            [
                (
                    "services remove".to_owned(),
                    AuditResult::Ok,
                    format!("removing {gateway}, {proxy} for sandbox stop")
                ),
                (
                    "services removed".to_owned(),
                    AuditResult::Ok,
                    format!("removed {gateway}, {proxy}")
                ),
                (
                    "sandbox stop".to_owned(),
                    AuditResult::Ok,
                    "removed 2 services, stopped 0 sessions".to_owned()
                ),
            ]
        );
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_stop_or_start_whose_first_entry_cannot_be_written_removes_nothing() {
        let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        engine.start_sandbox(&alice(), &name).unwrap();
        let from = engine.audit(None).unwrap().len();
        refusing_audit(&mut engine)
            .borrow_mut()
            .push("services remove");

        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::Audit(_)), "{err:?}");
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(matches!(err, Error::Audit(_)), "{err:?}");
        assert_eq!(fake.started.borrow().len(), 2);
        assert!(fake.stopped.borrow().is_empty());
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        assert_eq!(entries_after(&engine, from), []);
    }

    #[test]
    fn a_stop_whose_removal_fails_part_way_records_what_was_removed_and_what_is_left() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let [proxy, gateway] =
            [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
        engine.start_sandbox(&alice(), &name).unwrap();
        let from = engine.audit(None).unwrap().len();

        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::Service(_)), "{err:?}");
        assert!(err.to_string().contains("would not stop"), "{err}");
        assert_eq!(
            entries_after(&engine, from),
            [
                (
                    "services remove".to_owned(),
                    AuditResult::Ok,
                    format!("removing {gateway}, {proxy} for sandbox stop")
                ),
                (
                    "services removed".to_owned(),
                    AuditResult::Failed,
                    format!(
                        "removed {gateway}; could not remove {proxy}: would not stop {proxy}; still installed: {proxy}"
                    )
                ),
            ]
        );
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_removal_that_fails_and_cannot_be_recorded_says_both() {
        let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let [proxy, gateway] =
            [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
        engine.start_sandbox(&alice(), &name).unwrap();
        let from = engine.audit(None).unwrap().len();
        refusing_audit(&mut engine)
            .borrow_mut()
            .push("services removed");

        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::Unrecorded { .. }), "{err:?}");
        let text = err.to_string();
        assert!(
            text.starts_with(&format!(
                "would not stop {proxy}, but the audit log could not record it: "
            )),
            "{text}"
        );
        assert!(text.contains("disk full"), "{text}");
        assert_eq!(
            entries_after(&engine, from),
            [(
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {gateway}, {proxy} for sandbox stop")
            )]
        );
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_failed_start_records_the_removal_that_undoes_it() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let proxy = engine.label(&name, Unit::Proxy).unwrap();
        let from = engine.audit(None).unwrap().len();

        // The proxy is installed, then the gateway is refused.
        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());
        engine.start_sandbox(&alice(), &name).unwrap_err();
        let entries = entries_after(&engine, from);
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(entries[0].0, "sandbox start");
        assert_eq!(entries[0].1, AuditResult::Failed);
        assert_eq!(
            entries[1..],
            [
                (
                    "services remove".to_owned(),
                    AuditResult::Ok,
                    format!("removing {proxy} after a failed sandbox start")
                ),
                (
                    "services removed".to_owned(),
                    AuditResult::Ok,
                    format!("removed {proxy}")
                ),
            ]
        );

        // An undo that fails is recorded too.
        let from = engine.audit(None).unwrap().len();
        *fake.refuse_stop.borrow_mut() = Some(".proxy".to_owned());
        engine.start_sandbox(&alice(), &name).unwrap_err();
        let entries = entries_after(&engine, from);
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(entries[0].0, "sandbox start");
        assert_eq!(entries[0].1, AuditResult::Failed);
        assert_eq!(
            entries[1..],
            [
                (
                    "services remove".to_owned(),
                    AuditResult::Ok,
                    format!("removing {proxy} after a failed sandbox start")
                ),
                (
                    "services removed".to_owned(),
                    AuditResult::Failed,
                    format!(
                        "removed none; could not remove {proxy}: would not stop {proxy}; still installed: {proxy}"
                    )
                ),
            ]
        );
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_failed_start_removes_what_it_installed_even_when_that_cannot_be_recorded() {
        let (_dir, mut engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let proxy = engine.label(&name, Unit::Proxy).unwrap();
        let refused = refusing_audit(&mut engine);
        *fake.refuse.borrow_mut() = Some(".gateway".to_owned());

        // Without its first entry, the second records the whole removal.
        refused.borrow_mut().push("services remove");
        let from = engine.audit(None).unwrap().len();
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(matches!(err, Error::Service(_)), "{err:?}");
        assert!(
            fake.started.borrow().is_empty(),
            "the proxy stayed installed"
        );
        let entries = entries_after(&engine, from);
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].0, "sandbox start");
        assert_eq!(entries[0].1, AuditResult::Failed);
        assert_eq!(
            entries[1],
            (
                "services removed".to_owned(),
                AuditResult::Ok,
                format!("removed {proxy}")
            )
        );

        // Without either, the error says the cleanup worked.
        refused.borrow_mut().push("services removed");
        let from = engine.audit(None).unwrap().len();
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        let Error::CleanupUnrecorded { error, .. } = &err else {
            panic!("{err:?}");
        };
        assert!(matches!(**error, Error::Service(_)), "{error:?}");
        assert!(
            fake.started.borrow().is_empty(),
            "the proxy stayed installed"
        );
        let text = err.to_string();
        assert!(
            text.contains(&format!(
                "; cleaning up after it removed {proxy}, but the audit log could not record that: "
            )),
            "{text}"
        );
        assert!(!text.contains("failed too"), "{text}");
        let entries = entries_after(&engine, from);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].0, "sandbox start");
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_removal_whose_lock_then_times_out_leaves_the_entry_naming_it() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let [proxy, gateway] =
            [Unit::Proxy, Unit::Runtime(GATEWAY)].map(|u| engine.label(&name, u).unwrap());
        engine.start_sandbox(&alice(), &name).unwrap();
        let from = engine.audit(None).unwrap().len();

        // Another command takes the lock while the services are removed,
        // and keeps it past the wait.
        let other = SqliteStateStore::new(engine.layout.state_db(), engine.layout.state_lock());
        let held = Rc::new(RefCell::new(None));
        let holder = Rc::clone(&held);
        *fake.on_stop.borrow_mut() = Some(Box::new(move |_: &ServiceLabel| {
            if holder.borrow().is_none() {
                *holder.borrow_mut() = Some(other.lock().unwrap());
            }
        }));
        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        // Every service is gone; only the record of it is missing.
        let Error::Unrecorded { what, audit } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(*what, format!("removed {gateway}, {proxy}"));
        assert!(
            matches!(**audit, Error::State(StateError::Locked { .. })),
            "{audit:?}"
        );
        assert!(fake.started.borrow().is_empty());
        held.borrow_mut().take();
        // `sandbox stop` never ran, so the record still says running.
        assert_eq!(state_of(&engine, &name), SandboxState::Running);

        assert_eq!(
            entries_after(&engine, from),
            [(
                "services remove".to_owned(),
                AuditResult::Ok,
                format!("removing {gateway}, {proxy} for sandbox stop")
            )]
        );
        assert!(engine.verify_audit().unwrap().intact());
    }

    #[test]
    fn a_start_needs_the_service_manager_before_it_stops_anything() {
        let (_dir, engine, name) =
            super::policy::with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        let entries = engine.audit(None).unwrap().len();
        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("no service manager"), "{err}");
        // Refused before the audited start, with nothing changed.
        assert_eq!(engine.audit(None).unwrap().len(), entries);
        assert_eq!(state_of(&engine, &name), SandboxState::Created);
    }

    #[test]
    fn a_damaged_audit_log_refuses_start_and_stop_before_they_remove_services() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        engine.start_sandbox(&alice(), &name).unwrap();
        let path = engine.layout.audit_log();
        let text = std::fs::read_to_string(&path).unwrap();
        let damaged = text.replacen("\"init\"", "\"edited\"", 1);
        assert_ne!(damaged, text);
        std::fs::write(&path, &damaged).unwrap();

        let err = engine.start_sandbox(&alice(), &name).unwrap_err();
        assert!(err.to_string().contains("is damaged"), "{err}");
        let err = engine
            .stop_sandbox(&alice(), &name, Confirm::Yes)
            .unwrap_err();
        assert!(err.to_string().contains("is damaged"), "{err}");
        // Nothing was removed, so the sandbox keeps running.
        assert_eq!(fake.started.borrow().len(), 2);
        assert!(fake.stopped.borrow().is_empty());
        assert_eq!(state_of(&engine, &name), SandboxState::Running);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    }

    #[test]
    fn a_sandbox_with_services_installed_is_not_removed() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        engine.start_sandbox(&alice(), &name).unwrap();
        // Installed, though no proxy session was ever recorded: the proxy
        // could not take its port, and the service manager keeps restarting
        // it.
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        let err = engine
            .remove_sandbox(&alice(), &name, false, Confirm::Yes)
            .unwrap_err();
        assert!(matches!(err, Error::SandboxHasServices { .. }), "{err}");
        assert!(
            err.to_string().contains("enclos sandbox stop home"),
            "{err}"
        );
        assert_eq!(fake.started.borrow().len(), 1);

        done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        done(
            engine
                .remove_sandbox(&alice(), &name, false, Confirm::Yes)
                .unwrap(),
        );
    }

    #[test]
    fn stop_removes_every_service_under_the_sandbox_prefix_the_proxy_last() {
        let (_dir, engine, fake, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let labels = engine.start_sandbox(&alice(), &name).unwrap();
        let prefix = labels[0].as_str().strip_suffix("proxy").unwrap().to_owned();
        // Left by a runtime that no longer declares it, and by hand.
        fake.seed(&format!("{prefix}old-mail"));
        fake.seed(&format!("{prefix}archive"));
        fake.seed(&format!("{prefix}x.other"));
        // Another sandbox's, which shares the start of the prefix.
        let homework = format!("{}homework.proxy", prefix.strip_suffix("home.").unwrap());
        fake.seed(&homework);
        assert_eq!(
            labels_of(&engine.service_status(&name).unwrap()),
            [
                format!("{prefix}archive"),
                format!("{prefix}gateway"),
                format!("{prefix}old-mail"),
                format!("{prefix}x.other"),
                format!("{prefix}proxy"),
            ]
        );
        fake.stopped.borrow_mut().clear();
        done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        let stopped: Vec<String> = fake
            .stopped
            .borrow()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            stopped,
            [
                format!("{prefix}archive"),
                format!("{prefix}gateway"),
                format!("{prefix}old-mail"),
                format!("{prefix}x.other"),
                format!("{prefix}proxy"),
            ]
        );
        let left: Vec<String> = fake
            .started
            .borrow()
            .iter()
            .map(|u| u.label.to_string())
            .collect();
        assert_eq!(left, [homework]);
        assert!(engine.service_status(&name).unwrap().is_empty());
    }

    #[test]
    fn every_spelling_of_the_enclos_folder_names_the_same_services() {
        let (dir, engine, fake, name) = sandbox_with_services(None);
        engine.start_sandbox(&alice(), &name).unwrap();
        let proxy = engine.label(&name, Unit::Proxy).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("enclos"), &link).unwrap();
        let other = |alias: PathBuf| {
            let layout = Layout::at(alias);
            let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
            let audit = JsonlAuditLog::new(layout.audit_log());
            Engine::new(layout, Box::new(state), Box::new(audit), Vec::new())
                .with_services(Box::new(Rc::clone(&fake)))
        };
        for alias in [dir.path().join("enclos/."), link] {
            let other = other(alias);
            assert_eq!(other.label(&name, Unit::Proxy).unwrap(), proxy);
            assert_eq!(
                labels_of(&other.service_status(&name).unwrap()),
                [proxy.to_string()]
            );
        }
        // Stopped through another spelling, nothing stays installed.
        done(
            other(dir.path().join("enclos/."))
                .stop_sandbox(&alice(), &name, Confirm::Yes)
                .unwrap(),
        );
        assert!(fake.started.borrow().is_empty());
    }

    #[test]
    fn two_installs_never_share_a_service_label() {
        let (_one, first, _, name) = sandbox_with_services(None);
        let (_two, second, _, _) = sandbox_with_services(None);
        let (a, b) = (
            first.label(&name, Unit::Proxy).unwrap(),
            second.label(&name, Unit::Proxy).unwrap(),
        );
        assert_ne!(a, b);
        assert!(
            a.as_str().starts_with("enclos.") && a.as_str().ends_with(".home.proxy"),
            "{a}"
        );
        assert_eq!(a.as_str().len(), "enclos.12345678.home.proxy".len());
    }

    #[test]
    fn a_service_the_runtime_does_not_declare_is_refused() {
        let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let ended = std::sync::atomic::AtomicBool::new(false);
        let err = engine
            .launch_until(&alice(), &name, "mail", &ended)
            .unwrap_err();
        assert!(
            err.to_string().contains("no background service named mail"),
            "{err}"
        );
    }

    #[test]
    fn a_launch_told_to_end_before_its_proxy_runs_starts_nothing() {
        let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        let entries = engine.audit(None).unwrap().len();
        let ended = std::sync::atomic::AtomicBool::new(true);
        let err = engine
            .launch_until(&alice(), &name, "gateway", &ended)
            .unwrap_err();
        assert!(err.to_string().contains("told to end before"), "{err}");
        assert!(engine.state.sessions(&name, true).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), entries);
    }

    #[test]
    fn the_proxy_is_started_once_a_live_proxy_session_is_recorded() {
        let (_dir, engine, _, name) = sandbox_with_services(None);
        assert!(
            !engine
                .proxy_started(&name, Duration::from_millis(50))
                .unwrap()
        );
        stand_in_proxy(&engine, &name);
        assert!(engine.proxy_started(&name, Duration::ZERO).unwrap());
        let err = engine
            .proxy_started(&"nope".parse().unwrap(), Duration::ZERO)
            .unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
    }

    /// Records this process as the sandbox's proxy, which it stands in for.
    fn stand_in_proxy(engine: &Engine, name: &SandboxName) {
        let me = std::process::id();
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = engine.state.active_policy(name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Proxy,
                        service: None,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root: crate::lifecycle::process::reference(me)?.unwrap(),
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    engine.state.put_session(lock, &session)?;
                    Ok(())
                },
            )
            .unwrap();
    }

    #[test]
    fn a_stop_counts_the_session_of_a_service_it_removed_as_stopped_not_gone() {
        let (_dir, engine, fake, name) = sandbox_with_services(None);
        let label = engine.label(&name, Unit::Proxy).unwrap();
        fake.seed(label.as_str());
        // A sleep stands in for the proxy service's job, which ends when its
        // service is removed, before the stop looks at the sessions.
        let job = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let root = crate::lifecycle::process::reference(job.id())
            .unwrap()
            .unwrap();
        fake.jobs.borrow_mut().push((label.clone(), job));
        let id = engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let (version, snapshot) = engine.state.active_policy(&name)?.unwrap();
                    let session = crate::model::session::SessionRecord {
                        id: crate::model::session::SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Proxy,
                        service: None,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: None,
                        pgid: None,
                        root: root.clone(),
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    Ok(engine.state.put_session(lock, &session)?)
                },
            )
            .unwrap();

        let Planned::DryRun(plan) = engine
            .stop_sandbox(&alice(), &name, Confirm::DryRun)
            .unwrap()
        else {
            panic!("a dry run stopped the sandbox");
        };
        assert!(
            plan.changes
                .contains(&format!("stop session {id} (proxy, 1 processes)")),
            "{plan:?}"
        );
        let report = done(engine.stop_sandbox(&alice(), &name, Confirm::Yes).unwrap());
        assert!(fake.jobs.borrow().is_empty());
        assert_eq!(report.services, [label]);
        assert_eq!(report.stopped, [id]);
        assert!(report.gone.is_empty() && report.survivors.is_empty());
        let entries = engine.audit(None).unwrap();
        let finished = entries.last().unwrap().finished.as_ref().unwrap();
        assert_eq!(
            finished.outcome.message,
            "removed 1 services, stopped 1 sessions"
        );
        assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
    }

    #[test]
    fn a_launch_that_fails_marks_the_sandbox_failed_in_its_audited_write() {
        use super::sandbox::{assert_failed_by, without_backend};
        let (_dir, engine, _, name) = sandbox_with_services(Some(RuntimeKind::Hermes));
        stand_in_proxy(&engine, &name);
        let ended = std::sync::atomic::AtomicBool::new(false);
        let err = without_backend(&engine)
            .launch_until(&alice(), &name, GATEWAY.as_str(), &ended)
            .unwrap_err();
        assert!(matches!(err, Error::BackendUnavailable { .. }), "{err}");
        assert_failed_by(&engine, &name, "launch");
    }

    #[test]
    fn the_logs_are_the_log_files_of_the_sandbox_the_proxy_first() {
        let (_dir, engine, _, name) = sandbox_with_services(None);
        let err = engine.log_files(&"nope".parse().unwrap()).unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
        assert!(engine.log_files(&name).unwrap().is_empty());
        let logs = engine.layout.sandbox_dir("home").join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        for file in [
            "gateway.log",
            "proxy.log",
            "mail.log",
            "proxy.log.1",
            "notes",
        ] {
            std::fs::write(logs.join(file), "").unwrap();
        }
        let files: Vec<String> = engine
            .log_files(&name)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, ["proxy.log", "gateway.log", "mail.log"]);
    }
}

mod status {
    use std::path::Path;

    use super::policy::with_sandbox_on;
    use super::*;
    use crate::engine::status::suggest;
    use crate::engine::{AgentKind, AgentList, AgentStatus, Fact, Presence, SandboxStatus};
    use crate::model::Timestamp;
    use crate::model::agent::AgentName;
    use crate::model::runtime::RuntimeKind;
    use crate::model::session::{SessionId, SessionKind, SessionRecord};
    use crate::runtime::{
        HomeFile, Installer, RuntimeAdapter, RuntimeAgentName, SandboxCommand, Unreadable,
    };

    /// A runtime adapter that implements none of the `status` methods.
    struct Bare;

    impl RuntimeAdapter for Bare {
        fn kind(&self) -> RuntimeKind {
            RuntimeKind::Hermes
        }
        fn version(&self) -> &'static str {
            "0"
        }
        fn endpoints(&self) -> &'static str {
            ""
        }
        fn installer(&self) -> Installer {
            Installer {
                url: String::new(),
                args: Vec::new(),
            }
        }
        fn home_files(&self) -> Vec<HomeFile> {
            Vec::new()
        }
        fn login(&self) -> String {
            String::new()
        }
        fn create_agent(&self, _: &AgentName) -> SandboxCommand {
            SandboxCommand::from_words(&[])
        }
        fn agent_files(&self, _: &AgentName) -> String {
            String::new()
        }
        fn talk(&self, _: &AgentName) -> String {
            String::new()
        }
        fn services(&self) -> Vec<crate::runtime::RuntimeService> {
            Vec::new()
        }
        fn agents_in(&self, _: &Path) -> std::result::Result<Vec<RuntimeAgentName>, Unreadable> {
            Ok(Vec::new())
        }
    }

    fn with_runtime() -> (TempDir, Engine, SandboxName) {
        let (dir, engine, name) = with_sandbox_on(FakeBackend::available(BackendKind::Seatbelt));
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(&name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    Ok(())
                },
            )
            .unwrap();
        (dir, engine, name)
    }

    fn days(n: i64) -> jiff::SignedDuration {
        jiff::SignedDuration::from_hours(24 * n)
    }

    fn commands(s: &[Suggestion]) -> Vec<String> {
        s.iter().map(Suggestion::command).collect()
    }

    #[test]
    fn a_runtime_that_names_nothing_gets_sizes_no_agents_and_suggestions() {
        let (_dir, engine, name) = with_runtime();
        std::fs::write(engine.sandbox_home(&name).join("data"), vec![b'x'; 300_000]).unwrap();
        let record = engine.state.get(&name).unwrap().unwrap();
        let created = record.created_at;
        let status = engine.sandbox_status(record, Some(&Bare), created).unwrap();
        assert_eq!(status.disk.incomplete, None);
        assert!(status.disk.total >= 300_000);
        assert_eq!(status.disk.other, status.disk.total);
        assert_eq!(
            (status.disk.runtime, status.disk.caches, status.disk.agents),
            (None, None, None)
        );
        // A runtime that lists none: no agents, which is not "cannot tell".
        assert_eq!(
            status.agents,
            Some(AgentList {
                agents: Vec::new(),
                unreadable: None
            })
        );
        let rt = status.runtime.as_ref().unwrap();
        assert_eq!(
            (&rt.version, &rt.logged_in, &rt.installed),
            (&Fact::NotProvided, &Fact::NotProvided, &Fact::NotProvided)
        );
        assert_eq!(
            commands(&suggest(std::slice::from_ref(&status), created)),
            ["enclos agent add home/main"]
        );

        // Unused for 30 days, exactly, it is worth removing; a second less,
        // not yet.
        let at = |d| created.checked_add(d).unwrap();
        let almost = at(days(30) - jiff::SignedDuration::from_secs(1));
        assert_eq!(suggest(std::slice::from_ref(&status), almost).len(), 1);
        let s = suggest(std::slice::from_ref(&status), at(days(30)));
        assert_eq!(
            commands(&s),
            ["enclos agent add home/main", "enclos sandbox rm home"]
        );
        assert!(
            s[1].reason()
                .starts_with("unused for 30 days; removing it frees ")
        );
        assert!(!s[1].reason().contains('≥'), "{}", s[1].reason());
    }

    #[test]
    fn hermes_agents_logins_and_models_show_with_what_to_do() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        let scout = home.join(".hermes/profiles/scout");
        std::fs::create_dir_all(&scout).unwrap();
        std::fs::write(
            scout.join("config.yaml"),
            "model:\n  default: gpt-6.1-sol\n",
        )
        .unwrap();
        std::fs::write(scout.join(".hermes_history"), "hello").unwrap();
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        std::fs::write(home.join(".hermes/hermes-agent/big"), vec![b'x'; 200_000]).unwrap();
        // Hermes's own `default` profile, at the root of its home.
        std::fs::write(
            home.join(".hermes/config.yaml"),
            "model:\n  model: gpt-6.1-terra\n",
        )
        .unwrap();
        std::fs::write(home.join(".hermes/state.db"), vec![b'x'; 50_000]).unwrap();

        let view = engine.status(None).unwrap();
        let s = &view.sandboxes[0];
        let rt = s.runtime.as_ref().unwrap();
        assert_eq!(
            (&rt.logged_in, &rt.installed),
            (&Fact::Known(false), &Fact::Known(true))
        );
        let list = s.agents.as_ref().unwrap();
        assert_eq!(list.unreadable, None);
        assert_eq!(list.agents.len(), 2);
        let d = &list.agents[0];
        assert_eq!(
            (d.name.as_str(), d.kind, &d.model),
            (
                "default",
                AgentKind::Builtin,
                &Fact::Known("gpt-6.1-terra".into())
            )
        );
        // Its size is the root data, not the runtime install under it.
        let size = *d.bytes.known().unwrap();
        assert!((50_000..200_000).contains(&size), "{size}");
        assert!(d.last_active.known().is_some());
        let a = &list.agents[1];
        assert_eq!(
            (a.name.as_str(), a.kind, &a.model),
            (
                "scout",
                AgentKind::Untracked,
                &Fact::Known("gpt-6.1-sol".into())
            )
        );
        assert!(a.last_active.known().is_some() && *a.bytes.known().unwrap() > 0);
        assert!(s.disk.runtime.unwrap() >= 200_000);
        assert_eq!(
            commands(&view.suggestions),
            [
                "enclos agent add home/scout",
                "enclos connect home -- hermes -p default setup"
            ]
        );
        assert_eq!((view.agent_count(), view.untracked_count()), (1, 1));
        assert_eq!(engine.status(Some(&name)).unwrap().sandboxes.len(), 1);
        let err = engine.status(Some(&"nope".parse().unwrap())).unwrap_err();
        assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");

        // Logged in, the suggestion goes.
        std::fs::write(home.join(".hermes/auth.json"), "{}").unwrap();
        let view = engine.status(None).unwrap();
        assert_eq!(
            view.sandboxes[0].runtime.as_ref().unwrap().logged_in,
            Fact::Known(true)
        );
        assert_eq!(commands(&view.suggestions), ["enclos agent add home/scout"]);
    }

    #[test]
    fn enclos_neither_adds_nor_removes_the_built_in_agent() {
        let (_dir, engine, name) = with_runtime();
        let default: AgentName = "default".parse().unwrap();
        let audited = engine.audit(None).unwrap().len();
        let err = engine
            .add_agent(&alice(), &name, default.clone(), Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("is Hermes's built-in agent")
                && err
                    .to_string()
                    .contains("enclos connect home -- hermes -p default`"),
            "{err}"
        );
        let err = engine
            .remove_agent(&alice(), &name, &default, false, Confirm::Yes)
            .unwrap_err();
        assert!(
            err.to_string().contains("is Hermes's built-in agent"),
            "{err}"
        );
        assert!(engine.agents(&name).unwrap().is_empty());
        assert_eq!(engine.audit(None).unwrap().len(), audited);
        assert_eq!(
            engine.builtin_agent(&name).unwrap().map(|b| b.as_str()),
            Some("default")
        );
    }

    #[test]
    fn an_unreadable_agent_list_is_said_and_nothing_is_called_gone() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        std::fs::create_dir_all(home.join(".hermes/profiles/scout")).unwrap();
        std::fs::write(home.join(".hermes/profiles/scout/config.yaml"), "").unwrap();
        done(
            engine
                .add_agent(&alice(), &name, "scout".parse().unwrap(), Confirm::Yes)
                .unwrap(),
        );
        std::fs::rename(home.join(".hermes"), home.join("kept")).unwrap();
        std::os::unix::fs::symlink(home.join("kept"), home.join(".hermes")).unwrap();
        let view = engine.status(None).unwrap();
        let list = view.sandboxes[0].agents.as_ref().unwrap();
        assert_eq!(list.unreadable.as_deref(), Some("~/.hermes is a link"));
        let kinds: Vec<(&str, AgentKind)> = list
            .agents
            .iter()
            .map(|a| (a.name.as_str(), a.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("default", AgentKind::Builtin),
                (
                    "scout",
                    AgentKind::Tracked {
                        in_runtime: Presence::Unknown
                    }
                )
            ]
        );
        // Facts behind the link are not read either.
        assert!(matches!(&list.agents[1].model, Fact::CannotTell(why) if why.contains("link")));
        let rt = view.sandboxes[0].runtime.as_ref().unwrap();
        assert_eq!(rt.logged_in, Fact::CannotTell("~/.hermes is a link".into()));
        let s = &view.suggestions;
        assert_eq!(commands(s), ["enclos connect home"]);
        assert_eq!(
            s[0].reason(),
            "enclos cannot read Hermes's agents: ~/.hermes is a link"
        );
    }

    #[test]
    fn missing_runtime_files_suggest_installing_again_rather_than_logging_in() {
        let (_dir, engine, name) = with_runtime();
        std::fs::create_dir_all(engine.sandbox_home(&name).join(".hermes")).unwrap();
        let view = engine.status(None).unwrap();
        let rt = view.sandboxes[0].runtime.as_ref().unwrap();
        assert_eq!(rt.installed, Fact::Known(false));
        assert_eq!(
            commands(&view.suggestions),
            ["enclos runtime install hermes --sandbox home"]
        );
        assert_eq!(
            view.suggestions[0].reason(),
            "Hermes's files are missing from the home"
        );
    }

    /// A session of `kind`, started at `start`, ended at `end`.
    fn put_session(
        engine: &Engine,
        name: &SandboxName,
        kind: SessionKind,
        compiled: Option<&str>,
        start: Timestamp,
        end: Option<Timestamp>,
    ) {
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: name.clone(),
            kind,
            service: (kind == SessionKind::Service).then(|| "gateway".to_owned()),
            version: 1,
            snapshot: engine.policy(name).unwrap().snapshot.id,
            compiled: compiled.map(str::to_owned),
            root: crate::lifecycle::process::reference(std::process::id())
                .unwrap()
                .unwrap(),
            pgid: None,
            tracked: Vec::new(),
            started_at: start,
            ended_at: end,
        };
        let lock = engine.state.lock().unwrap();
        engine.state.put_session(&lock, &session).unwrap();
    }

    fn net_event(name: &SandboxName, at: Timestamp, denied: bool) -> crate::model::net::NetEvent {
        use crate::model::net::{NetEvent, Reason, Verdict};
        NetEvent {
            at,
            sandbox: name.clone(),
            host: "example.com".into(),
            port: 443,
            method: "CONNECT".into(),
            address: None,
            verdict: if denied {
                Verdict::Denied
            } else {
                Verdict::Allowed
            },
            reason: denied.then_some(Reason::NotAllowed),
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
            name_seen: None,
        }
    }

    #[test]
    fn the_last_use_counts_connect_and_service_sessions_and_the_network_not_the_proxy() {
        use crate::engine::status::last_used;
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let at = |d: i64| t0.checked_add(days(d)).unwrap();
        let session = |kind, start, end| SessionRecord {
            id: SessionId(0),
            sandbox: "home".parse().unwrap(),
            kind,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("x".into()),
            compiled: None,
            root: crate::lifecycle::process::reference(std::process::id())
                .unwrap()
                .unwrap(),
            pgid: None,
            tracked: Vec::new(),
            started_at: start,
            ended_at: end,
        };
        assert_eq!(last_used(t0, &[], None), t0);
        // A `connect` from day 1 to day 5, a service that ended on day 9, a
        // proxy that ran until day 20, and a connection tried on day 7.
        let sessions = [
            session(SessionKind::Interactive, at(1), Some(at(5))),
            session(SessionKind::Service, at(2), Some(at(9))),
            session(SessionKind::Proxy, at(3), Some(at(20))),
        ];
        assert_eq!(last_used(t0, &sessions, Some(at(7))), at(9));
        assert_eq!(last_used(t0, &sessions[2..], Some(at(7))), at(7));
        assert_eq!(last_used(t0, &sessions[..1], None), at(5));
    }

    #[test]
    fn sessions_and_the_network_log_give_last_connect_and_what_needs_a_restart() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let t0 = record.created_at;
        let fresh = engine
            .sandbox_status(record.clone(), Some(&Bare), t0)
            .unwrap();
        assert_eq!(
            (fresh.last_connect, fresh.last_network, fresh.last_used),
            (None, None, t0)
        );
        assert!(!fresh.restart_needed && fresh.running_sessions == 0);
        assert!(!fresh.in_use());

        let later = t0.checked_add(jiff::SignedDuration::from_secs(60)).unwrap();
        put_session(&engine, &name, SessionKind::Interactive, None, later, None);
        engine
            .state
            .record(&net_event(&name, later, false))
            .unwrap();
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), later)
            .unwrap();
        assert_eq!(
            (status.last_connect, status.last_network, status.last_used),
            (Some(later), Some(later), later)
        );
        assert_eq!(status.running_sessions, 1);
        assert!(status.in_use());
        // A session without a compiled file, as the proxy runs, applies
        // network rules live: no restart. One on a compiled file the active
        // policy replaced needs one.
        assert!(!status.restart_needed);
        put_session(
            &engine,
            &name,
            SessionKind::Interactive,
            Some("/old/compiled.sb"),
            later,
            None,
        );
        let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
        assert!(status.restart_needed);
        assert!(
            commands(&suggest(&[status], later)).contains(&"enclos sandbox restart home".into())
        );
    }

    #[test]
    fn a_sandbox_that_cannot_be_read_is_listed_with_why_and_the_total_is_a_lower_bound() {
        let (_dir, engine, name) = with_runtime();
        let spec = crate::engine::SandboxSpec {
            name: "spare".parse().unwrap(),
            backend: BackendKind::Seatbelt,
            template: "assistant".parse().unwrap(),
        };
        done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
        assert!(engine.status(None).unwrap().complete);
        put_session(
            &engine,
            &name,
            SessionKind::Interactive,
            None,
            crate::model::now(),
            None,
        );
        let db = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
        db.execute("UPDATE sessions SET started_at = 'not a time'", [])
            .unwrap();
        let view = engine.status(None).unwrap();
        let listed: Vec<&str> = view.sandboxes.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(listed, ["spare"]);
        assert_eq!(view.unlisted.len(), 1);
        assert_eq!(view.unlisted[0].name, name);
        assert!(!view.unlisted[0].error.is_empty());
        // Its folder is not in `bytes`, so the total is a lower bound.
        assert!(!view.complete);
    }

    #[test]
    fn refused_destinations_count_for_seven_days_exactly() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let now = record.created_at.checked_add(days(20)).unwrap();
        let week = now.checked_sub(days(7)).unwrap();
        engine.state.record(&net_event(&name, week, true)).unwrap();
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), now)
            .unwrap();
        assert_eq!(status.refused_recently, 1);
        let s = suggest(std::slice::from_ref(&status), now);
        assert!(
            commands(&s).contains(&"enclos net denied home".into()),
            "{s:?}"
        );
        let later = now.checked_add(jiff::SignedDuration::from_secs(1)).unwrap();
        let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
        assert_eq!(status.refused_recently, 0);
    }

    #[test]
    fn a_refusal_because_the_policy_was_unreadable_is_not_a_destination_to_review() {
        use crate::model::net::Reason;
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let now = record.created_at.checked_add(days(1)).unwrap();
        let mut event = net_event(&name, now, true);
        event.reason = Some(Reason::PolicyUnreadable);
        engine.state.record(&event).unwrap();
        // `net denied` still lists it, with its reason.
        let denied = engine.net_denied(&name).unwrap();
        assert_eq!(denied.len(), 1, "{denied:?}");
        assert_eq!(denied[0].reason, Reason::PolicyUnreadable);
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), now)
            .unwrap();
        assert_eq!(status.refused_recently, 0);
        assert_eq!(status.policy_unreadable_at, Some(now));
        // Not a destination to review, but a proxy to look at.
        let s = suggest(std::slice::from_ref(&status), now);
        let listed = commands(&s);
        assert!(!listed.contains(&"enclos net denied home".into()), "{s:?}");
        assert!(listed.contains(&"enclos logs home".into()), "{s:?}");

        // A real refusal beside it is still one to review.
        let mut other = net_event(&name, now, true);
        other.host = "evil.example.com".into();
        engine.state.record(&other).unwrap();
        let status = engine
            .sandbox_status(record.clone(), Some(&Bare), now)
            .unwrap();
        assert_eq!(status.refused_recently, 1);
        let listed = commands(&suggest(std::slice::from_ref(&status), now));
        assert!(
            listed.contains(&"enclos net denied home".into()),
            "{listed:?}"
        );
        assert!(listed.contains(&"enclos logs home".into()), "{listed:?}");

        // After 7 days, neither is suggested.
        let later = now.checked_add(days(8)).unwrap();
        let status = engine.sandbox_status(record, Some(&Bare), later).unwrap();
        assert_eq!(status.policy_unreadable_at, None);
        assert_eq!(status.refused_recently, 0);
    }

    #[test]
    fn each_rule_names_its_command_and_nothing_fires_without_its_fact() {
        let (_dir, engine, name) = with_runtime();
        let record = engine.state.get(&name).unwrap().unwrap();
        let t0 = record.created_at;
        let base = engine.sandbox_status(record, Some(&Bare), t0).unwrap();
        let with_agents = |agents: Vec<(&str, AgentKind)>| SandboxStatus {
            agents: Some(AgentList {
                agents: agents
                    .into_iter()
                    .map(|(n, kind)| AgentStatus {
                        name: crate::runtime::RuntimeAgentName::new(n).unwrap(),
                        kind,
                        last_active: Fact::NotProvided,
                        bytes: Fact::NotProvided,
                        model: Fact::NotProvided,
                    })
                    .collect(),
                unreadable: None,
            }),
            ..base.clone()
        };
        let s = with_agents(vec![
            ("default", AgentKind::Builtin),
            (
                "main",
                AgentKind::Tracked {
                    in_runtime: Presence::Present,
                },
            ),
            (
                "gone",
                AgentKind::Tracked {
                    in_runtime: Presence::Gone,
                },
            ),
            (
                "lost",
                AgentKind::Tracked {
                    in_runtime: Presence::Unknown,
                },
            ),
            ("scout", AgentKind::Untracked),
            ("my_bot", AgentKind::Untrackable),
        ]);
        // The two counts split every agent of every sandbox.
        let other = with_agents(vec![("bot", AgentKind::Untracked)]);
        let mut view = engine.status(None).unwrap();
        view.sandboxes = vec![s.clone(), other];
        assert_eq!((view.agent_count(), view.untracked_count()), (4, 3));
        assert_eq!(
            commands(&suggest(&[s], t0)),
            ["enclos agent rm home/gone", "enclos agent add home/scout"]
        );
        let none = SandboxStatus {
            runtime: None,
            agents: None,
            ..base.clone()
        };
        assert_eq!(
            commands(&suggest(&[none], t0)),
            ["enclos runtime install <runtime> --sandbox home"]
        );

        // Something running, or a service manager that cannot say, keeps an
        // old sandbox from being called unused.
        let old = t0.checked_add(days(40)).unwrap();
        let idle = with_agents(vec![("default", AgentKind::Builtin)]);
        assert_eq!(
            commands(&suggest(std::slice::from_ref(&idle), old)),
            ["enclos sandbox rm home"]
        );
        let running = SandboxStatus {
            running_sessions: 1,
            ..idle.clone()
        };
        let unknown = SandboxStatus {
            services: Fact::CannotTell("no GUI domain".into()),
            ..idle.clone()
        };
        let service = SandboxStatus {
            services: Fact::Known(vec![crate::engine::ServiceLine {
                label: "enclos.x.home.gateway".into(),
                service: "gateway".into(),
                state: crate::engine::ServiceState::Running { pid: 1 },
            }]),
            ..idle.clone()
        };
        for busy in [running, unknown, service] {
            assert!(suggest(&[busy], old).is_empty());
        }
        // A walk that stopped early says the size is a lower bound.
        let partial = SandboxStatus {
            disk: crate::engine::Disk {
                incomplete: Some("stopped after 1000000 entries".into()),
                ..idle.disk.clone()
            },
            ..idle
        };
        let s = suggest(&[partial], old);
        assert!(s[0].reason().contains("frees ≥ "), "{}", s[0].reason());
    }

    #[test]
    fn the_json_view_names_each_state_and_fact() {
        let (_dir, engine, name) = with_runtime();
        let home = engine.sandbox_home(&name);
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let json = serde_json::to_value(engine.status(None).unwrap()).unwrap();
        let s = &json["sandboxes"][0];
        assert_eq!(s["name"], "home");
        assert_eq!(s["state"], "created");
        assert_eq!(s["services"], serde_json::json!({"known": []}));
        assert_eq!(s["runtime"]["kind"], "hermes");
        assert_eq!(s["runtime"]["version"], "not_provided");
        assert_eq!(
            s["runtime"]["logged_in"],
            serde_json::json!({"known": false})
        );
        let default = &s["agents"]["agents"][0];
        assert_eq!(default["name"], "default");
        assert_eq!(default["kind"], "builtin");
        assert_eq!(default["model"], "absent");
        assert!(s["disk"]["total"].is_u64());
        assert_eq!(s["disk"]["incomplete"], serde_json::Value::Null);
        // The gateway is not running, and nothing in the sandbox listens.
        assert_eq!(s["dashboard"], "absent");
        assert_eq!(s["network_listeners"], serde_json::json!({"known": []}));
        assert_eq!(json["complete"], true);
        assert_eq!(json["idle_days"], 30);
        assert!(json["bytes"].is_u64());
        assert_eq!(json["unlisted"], serde_json::json!([]));
        assert_eq!(
            json["suggestions"][0],
            serde_json::json!({
                "kind": "log_in",
                "target": "home",
                "reason": "Hermes is not logged in",
                "command": "enclos connect home -- hermes -p default setup"
            })
        );
    }
}

/// The runtime's own service, whose port the sandbox's sessions reach (ADR
/// 0028). The stand-in gateways are `perl`.
mod listener {
    use super::policy::with_sandbox;
    use super::*;
    use crate::engine::listener::{NoPort, outside_proxy_range, service_listener};
    use crate::model::runtime::RuntimeKind;
    use crate::model::session::{ProcessRef, SessionId, SessionKind, SessionRecord};

    /// A stand-in gateway: `perl` running `script`, which prints each port
    /// it listens on, one a line, then waits.
    fn perl(script: &str, ports: usize) -> (std::process::Child, Vec<u16>) {
        use std::io::BufRead;
        let mut child = std::process::Command::new("/usr/bin/perl")
            .args(["-MSocket=:all", "-e", script])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let ports = (0..ports)
            .map(|_| lines.next().unwrap().unwrap().parse().unwrap())
            .collect();
        (child, ports)
    }

    /// `ports` loopback listeners on ports the system chooses, as Hermes's
    /// gateway binds `127.0.0.1:0`.
    fn listening(ports: usize, at: &str) -> String {
        format!(
            "for (1..{ports}) {{ socket(my $s, PF_INET, SOCK_STREAM, 0) or die; bind($s, sockaddr_in(0, inet_aton(\"{at}\"))) or die; listen($s, 1) or die; push @s, $s; print((sockaddr_in(getsockname($s)))[0], qq(\\n)); }} $| = 1; STDOUT->flush; sleep 30"
        )
    }

    /// Records `root` as an open session of the sandbox's `gateway`, and
    /// Hermes as its runtime.
    pub(super) fn record_gateway(engine: &Engine, name: &SandboxName, root: ProcessRef) {
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| {
                    let mut record = engine.state.get(name)?.unwrap();
                    record.runtime = Some(RuntimeKind::Hermes);
                    engine.state.put(lock, &record)?;
                    let session = SessionRecord {
                        id: SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Service,
                        service: Some("gateway".to_owned()),
                        version: 1,
                        snapshot: engine.policy(name)?.snapshot.id,
                        compiled: None,
                        root,
                        pgid: None,
                        tracked: Vec::new(),
                        started_at: crate::model::now(),
                        ended_at: None,
                    };
                    engine.state.start_session(lock, &session, &record)?;
                    Ok(())
                },
            )
            .unwrap();
    }

    /// A stand-in gateway listening on `ports` ports at 127.0.0.1, recorded
    /// as the open session of the sandbox's `gateway` service.
    pub(super) fn gateway(
        engine: &Engine,
        name: &SandboxName,
        ports: usize,
    ) -> (std::process::Child, u16) {
        let (child, held) = perl(&listening(ports, "127.0.0.1"), ports);
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        record_gateway(engine, name, root);
        (child, held[0])
    }

    pub(super) fn end(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn connect_waits_for_nothing_when_the_gateway_listens() {
        let (_dir, engine, name) = with_sandbox();
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let (child, _) = gateway(&engine, &name, 1);
        let got = engine.start_listener_service(&alice(), &name, &mut |_| panic!("said"));
        end(child);
        assert_eq!(got.unwrap(), None);
    }

    /// What waiting does not fix ends the wait at once.
    #[test]
    fn connect_stops_waiting_at_once_for_a_gateway_refused() {
        let (_dir, engine, name) = with_sandbox();
        let home = engine.layout.sandbox_home(name.as_str());
        std::fs::create_dir_all(home.join(".hermes/hermes-agent")).unwrap();
        let (child, _) = gateway(&engine, &name, 2);
        let begun = std::time::Instant::now();
        let got = engine.start_listener_service(&alice(), &name, &mut |_| {});
        end(child);
        assert!(begun.elapsed() < std::time::Duration::from_secs(10));
        let waited = got.unwrap().unwrap();
        assert!(!waited.started);
        let late = waited.late.unwrap();
        assert!(late.contains("listens on 2 ephemeral ports"), "{late}");
    }

    #[test]
    fn the_service_port_is_the_one_its_own_process_holds() {
        let (_dir, engine, name) = with_sandbox();
        assert_eq!(
            engine.service_port(&engine.record(&name).unwrap()),
            Ok(None)
        );
        let (child, port) = gateway(&engine, &name, 1);
        let record = engine.record(&name).unwrap();
        assert_eq!(engine.service_port(&record), Ok(Some(port)));
        end(child);
        // Gone: no port, and the session is told why and what to do.
        let why = engine.service_port(&record).unwrap_err();
        assert!(why.contains("the gateway is not running"), "{why}");
        assert!(why.contains("enclos sandbox start home"), "{why}");
    }

    #[test]
    fn a_service_holding_several_ports_gets_none_rather_than_a_guess() {
        let (_dir, engine, name) = with_sandbox();
        let (child, _) = gateway(&engine, &name, 2);
        let got = service_listener(engine.state.as_ref(), &name, "gateway");
        end(child);
        assert!(
            matches!(&got, Err(NoPort::Refused(why)) if why.contains("listens on 2 ephemeral ports")),
            "{got:?}"
        );
    }

    #[test]
    fn two_open_gateway_sessions_get_none_rather_than_a_guess() {
        let (_dir, engine, name) = with_sandbox();
        let (one, _) = gateway(&engine, &name, 1);
        let (two, _) = gateway(&engine, &name, 1);
        let got = service_listener(engine.state.as_ref(), &name, "gateway");
        end(one);
        end(two);
        assert!(
            matches!(&got, Err(NoPort::Refused(why)) if why.contains("2 gateway sessions are running")),
            "{got:?}"
        );
    }

    #[test]
    fn a_pid_now_another_processs_is_not_taken_for_the_gateway() {
        let (_dir, engine, name) = with_sandbox();
        // This test process listens, under the gateway's recorded pid but
        // not its start time, as when the pid was reused.
        let _listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let root = ProcessRef {
            pid: std::process::id(),
            started: "Thu Jan  1 00:00:00 1970".to_owned(),
        };
        record_gateway(&engine, &name, root);
        let got = service_listener(engine.state.as_ref(), &name, "gateway");
        assert!(
            matches!(&got, Err(NoPort::NotRunning(why)) if why.contains("not running")),
            "{got:?}"
        );
    }

    #[test]
    fn a_gateway_on_every_address_or_sharing_its_port_gets_none() {
        // On every address: another process could hold 127.0.0.1 there.
        let (_dir, engine, name) = with_sandbox();
        let (child, held) = perl(&listening(1, "0.0.0.0"), 1);
        record_gateway(
            &engine,
            &name,
            crate::lifecycle::process::reference_of_child(&child).unwrap(),
        );
        let got = service_listener(engine.state.as_ref(), &name, "gateway");
        end(child);
        assert!(
            matches!(&got, Err(NoPort::NotYet(why)) if why.contains("no TCP listener at 127.0.0.1")),
            "{held:?}"
        );

        // Sharing 127.0.0.1 at its port with another process (SO_REUSEPORT):
        // a session could reach that one too.
        let (_dir, engine, name) = with_sandbox();
        let shared = "socket(my $s, PF_INET, SOCK_STREAM, 0) or die; setsockopt($s, SOL_SOCKET, SO_REUSEPORT, 1) or die; bind($s, sockaddr_in($ARGV[0] // 0, INADDR_LOOPBACK)) or die; listen($s, 1) or die; print((sockaddr_in(getsockname($s)))[0], qq(\\n)); $| = 1; STDOUT->flush; sleep 30";
        let (owner, port) = perl(shared, 1);
        let mut other = std::process::Command::new("/usr/bin/perl")
            .args(["-MSocket=:all", "-e", shared, &port[0].to_string()])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::BufRead;
            let mut lines = std::io::BufReader::new(other.stdout.take().unwrap()).lines();
            assert_eq!(lines.next().unwrap().unwrap(), port[0].to_string());
        }
        record_gateway(
            &engine,
            &name,
            crate::lifecycle::process::reference_of_child(&owner).unwrap(),
        );
        let got = service_listener(engine.state.as_ref(), &name, "gateway");
        end(owner);
        end(other);
        let why = got.unwrap_err();
        assert!(
            matches!(&why, NoPort::Refused(why) if why.contains("also listens at 127.0.0.1")),
            "{why:?}"
        );
    }

    fn status_of(engine: &Engine, name: &SandboxName) -> crate::engine::SandboxStatus {
        let mut view = engine.status(Some(name)).unwrap();
        view.sandboxes.remove(0)
    }

    /// Status shows the dashboard at the port sessions are given, nothing
    /// once the gateway is gone, and why when the port cannot be trusted.
    #[test]
    fn status_shows_the_dashboard_at_the_gateways_port() {
        use crate::engine::Fact;
        let (_dir, engine, name) = with_sandbox();
        let (child, port) = gateway(&engine, &name, 1);
        let up = status_of(&engine, &name);
        end(child);
        assert_eq!(
            up.dashboard,
            Fact::Known(format!("http://127.0.0.1:{port}/"))
        );
        // On loopback alone: nothing the host's network reaches.
        assert_eq!(up.network_listeners, Fact::Known(Vec::new()));
        assert_eq!(status_of(&engine, &name).dashboard, Fact::Absent);

        let (_dir, engine, name) = with_sandbox();
        let (child, _) = gateway(&engine, &name, 2);
        let several = status_of(&engine, &name);
        end(child);
        let Fact::CannotTell(why) = several.dashboard else {
            panic!("{:?}", several.dashboard);
        };
        assert!(why.contains("listens on 2 ephemeral ports"), "{why}");

        // On every address: no dashboard, and the gateway is named as what
        // the host's network reaches.
        let (_dir, engine, name) = with_sandbox();
        let (child, held) = perl(&listening(1, "0.0.0.0"), 1);
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        record_gateway(&engine, &name, root);
        let wide = status_of(&engine, &name);
        end(child);
        assert!(
            matches!(wide.dashboard, Fact::CannotTell(_)),
            "{:?}",
            wide.dashboard
        );
        let Fact::Known(reached) = wide.network_listeners else {
            panic!("{:?}", wide.network_listeners);
        };
        assert_eq!(reached.len(), 1, "{reached:?}");
        assert_eq!(reached[0].address, format!("*:{}", held[0]));
    }

    #[test]
    fn a_proxy_port_is_never_a_sessions_service_port() {
        use crate::model::sandbox::{PORT_FIRST, PORT_LAST};
        assert!(outside_proxy_range(PORT_FIRST).is_err());
        assert!(outside_proxy_range(PORT_LAST).is_err());
        assert_eq!(outside_proxy_range(61374), Ok(61374));
    }
}

mod doctor;
mod exec;
mod history;
mod pending;
mod proxy_socket;
mod secrets;
// `state check` lists program files with `lsof`, which only macOS has here.
#[cfg(target_os = "macos")]
mod state_check;
