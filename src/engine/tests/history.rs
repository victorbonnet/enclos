//! A sandbox's policy history: versions, diffs, rollbacks and refreshes
//! (design §7, ADR 0018).

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::engine::{ChangeOutcome, Side};
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::policy::AdapterLayer;

fn allow(engine: &Engine, name: &SandboxName, host: &str) {
    done(
        engine
            .policy_allow(&alice(), name, host, Confirm::Yes)
            .unwrap(),
    );
}

/// A sandbox `home` at v3: v2 allows a.example.com, v3 b.example.com too.
fn with_three_versions() -> (TempDir, Engine, SandboxName) {
    let (dir, engine, name) = with_sandbox();
    allow(&engine, &name, "a.example.com");
    allow(&engine, &name, "b.example.com");
    (dir, engine, name)
}

#[test]
fn the_history_lists_every_version_oldest_first() {
    let (_dir, engine, name) = with_three_versions();
    let history = engine.policy_history(&name).unwrap();
    let versions: Vec<u32> = history.versions.iter().map(|v| v.version).collect();
    assert_eq!(versions, [1, 2, 3]);
    assert_eq!(history.active().unwrap().version, 3);
    assert!(history.pending.is_none());
}

#[test]
fn a_diff_compares_the_version_before_by_default_or_the_versions_asked() {
    let (_dir, engine, name) = with_three_versions();
    let diff = engine.policy_diff(&name, None, None).unwrap();
    assert_eq!((diff.from, diff.to), (2, Side::Version(3)));
    assert_eq!(diff.changes, ["allow b.example.com"]);
    let diff = engine.policy_diff(&name, Some(3), Some(1)).unwrap();
    assert_eq!(
        diff.changes,
        ["stop allowing a.example.com", "stop allowing b.example.com"]
    );
    let diff = engine.policy_diff(&name, Some(1), Some(1)).unwrap();
    assert!(diff.changes.is_empty() && diff.inputs.is_empty());
    let err = engine.policy_diff(&name, Some(9), None).unwrap_err();
    assert!(
        matches!(err, Error::NoSuchPolicyVersion { last: 3, .. }),
        "{err}"
    );
}

#[test]
fn a_diff_shows_the_pending_policy_by_default() {
    let (dir, engine, name) = with_sandbox();
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let before = engine.layout.read_policy("home").unwrap();
    let after = before.replace(
        "write_add = []",
        &format!("write_add = [\"{}\"]", work.display()),
    );
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let diff = engine.policy_diff(&name, None, None).unwrap();
    assert_eq!((diff.from, diff.to), (1, Side::Pending));
    assert_eq!(diff.changes.len(), 1);
    assert!(diff.changes[0].contains(&work.display().to_string()));
}

#[test]
fn a_rollback_restores_the_version_and_its_policy_toml() {
    let (_dir, engine, name) = with_three_versions();
    let v1 = engine.state.policy_version(&name, 1).unwrap().unwrap().1;

    let planned = engine
        .policy_rollback(&alice(), &name, 1, Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert_eq!(plan.changes.len(), 3, "{plan:?}");
    assert!(
        plan.changes[1].contains("stop allowing a.example.com"),
        "{plan:?}"
    );
    assert_eq!(engine.policy(&name).unwrap().version.version, 3);

    // Named by its version, as an edit names its file: nothing more to ask.
    let applied = done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    assert_eq!(applied.version.version, 4);
    assert_eq!(applied.version.restores, Some(1));
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.snapshot.id, v1.id, "the very snapshot of v1");
    // Later edits start from v1's policy.toml.
    assert_eq!(
        engine.layout.read_policy("home").unwrap(),
        v1.overrides_text().unwrap()
    );
    let last = engine.audit(None).unwrap().pop().unwrap();
    assert_eq!(last.intent.command, "policy rollback");
    assert_eq!(last.intent.target.as_deref(), Some("home v1"));

    // Rolling back to what is in force changes nothing.
    let again = done(
        engine
            .policy_rollback(&alice(), &name, 4, Confirm::Ask)
            .unwrap(),
    );
    assert!(!again.changed);
    let err = engine
        .policy_rollback(&alice(), &name, 7, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::NoSuchPolicyVersion { .. }), "{err}");
}

#[test]
fn a_rollback_while_sessions_run_waits_as_pending_and_records_what_it_restores() {
    let (dir, engine, name) = with_sandbox();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let before = engine.layout.read_policy("home").unwrap();
    let after = before.replace(
        "write_add = []",
        &format!("write_add = [\"{}\"]", work.display()),
    );
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);

    // v1 drops the write grant, which the running session keeps.
    let applied = done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Ask)
            .unwrap(),
    );
    let ChangeOutcome::Pending(pending) = &applied.outcome else {
        panic!("{applied:?}")
    };
    assert_eq!(pending.restores, Some(1));
    assert_eq!(engine.policy(&name).unwrap().version.version, 2);
    assert_eq!(
        engine
            .policy_history(&name)
            .unwrap()
            .pending
            .unwrap()
            .restores,
        Some(1)
    );
    // A rollback over a change pending asks before it drops it.
    let err = engine
        .policy_rollback(&alice(), &name, 2, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(err.to_string().contains("drop the pending policy"), "{err}");
    drop(sleeping);
    let restarted = done(engine.policy_apply(&alice(), &name, Confirm::Yes).unwrap());
    assert_eq!(restarted.version.restores, Some(1));
}

#[test]
fn a_rollback_over_an_edit_not_applied_is_refused() {
    let (_dir, engine, name) = with_three_versions();
    let text = engine.layout.read_policy("home").unwrap();
    engine
        .layout
        .write_policy("home", &format!("{text}# a note\n"))
        .unwrap();
    let err = engine
        .policy_rollback(&alice(), &name, 1, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::PolicyFileEdited { .. }), "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 3);
}

#[test]
fn a_rollback_to_a_version_whose_policy_toml_is_unknown_says_so() {
    let (_dir, engine, name) = with_three_versions();
    let id = engine.state.policy_version(&name, 1).unwrap().unwrap().1.id;
    let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
    conn.execute(
        "UPDATE policy_snapshots SET overrides = '' WHERE id = ?1",
        [&id.0],
    )
    .unwrap();
    let err = engine
        .policy_rollback(&alice(), &name, 1, Confirm::Yes)
        .unwrap_err();
    assert!(
        matches!(err, Error::PolicyTextUnknown { version: 1, .. }),
        "{err}"
    );
}

/// Records Hermes as the sandbox's runtime, and makes its active policy one
/// resolved with an older adapter layer, as after an upgrade of enclos.
fn with_an_older_adapter(engine: &Engine, name: &SandboxName) {
    let older = AdapterLayer {
        runtime: "hermes".into(),
        version: "0.0.1".into(),
        text: "[network]\nallow_add = [\"old.example.com\"]\n".into(),
    };
    with_adapter(engine, name, older);
}

/// Records Hermes as the sandbox's runtime, and makes its active policy one
/// resolved with the adapter layer `older`.
fn with_adapter(engine: &Engine, name: &SandboxName, older: AdapterLayer) {
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
                let text = engine.layout.read_policy(name.as_str())?;
                let snapshot =
                    engine.checked_policy_with(name, &text, Some(older), BackendKind::Seatbelt)?;
                engine.store_policy(lock, &alice(), name, &text, &snapshot, None)
            },
        )
        .unwrap();
}

#[test]
fn a_refresh_changes_nothing_while_the_policy_resolves_the_same() {
    let (_dir, engine, name) = with_three_versions();
    let applied = done(
        engine
            .policy_refresh(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(!applied.changed);
    assert_eq!(applied.version.version, 3);
}

#[test]
fn a_refresh_lists_what_a_newer_adapter_changes_and_applies_it_once_accepted() {
    let (_dir, engine, name) = with_sandbox();
    with_an_older_adapter(&engine, &name);
    let before = engine.policy(&name).unwrap();
    assert!(
        before
            .snapshot
            .policy
            .net
            .allow
            .contains(&"old.example.com".to_owned())
    );

    // New sessions keep the stored snapshot until the refresh is accepted.
    let err = engine
        .policy_refresh(&alice(), &name, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(
        err.to_string().contains("stop allowing old.example.com"),
        "{err}"
    );
    assert_eq!(
        engine.policy(&name).unwrap().snapshot.id,
        before.snapshot.id
    );

    let applied = done(
        engine
            .policy_refresh(&alice(), &name, Confirm::Yes)
            .unwrap(),
    );
    assert!(applied.changed);
    let after = engine.policy(&name).unwrap();
    assert_eq!(after.version.version, before.version.version + 1);
    assert!(
        !after
            .snapshot
            .policy
            .net
            .allow
            .contains(&"old.example.com".to_owned())
    );
    assert!(
        after
            .snapshot
            .policy
            .net
            .allow
            .contains(&"chatgpt.com".to_owned())
    );
    let diff = engine.policy_diff(&name, None, None).unwrap();
    assert!(
        diff.inputs.iter().any(|i| i.contains("hermes adapter")),
        "{diff:?}"
    );
    assert_eq!(
        engine.audit(None).unwrap().pop().unwrap().intent.command,
        "policy refresh"
    );
}

/// A write grant for `dir/<folder>`, made as v2 while nothing runs.
fn grant_v2(dir: &TempDir, engine: &Engine, name: &SandboxName, folder: &str) -> String {
    let work = dir.path().join(folder);
    std::fs::create_dir_all(&work).unwrap();
    let work = work.display().to_string();
    let before = engine.layout.read_policy("home").unwrap();
    let after = before.replace("write_add = []", &format!("write_add = [\"{work}\"]"));
    done(
        engine
            .policy_edit(&alice(), name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    work
}

/// A session running under a compiled policy, ended when dropped.
fn running(engine: &Engine, name: &SandboxName) -> Sleeping {
    let sleeping = Sleeping::new();
    let mut session = session_of(engine, name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(engine, &session);
    sleeping
}

/// Makes the edit of `policy.toml` from `from` to `to` pending.
fn pending_edit(engine: &Engine, name: &SandboxName, from: &str, to: &str) {
    let before = engine.layout.read_policy("home").unwrap();
    let after = before.replace(from, to);
    let applied = done(
        engine
            .policy_edit(&alice(), name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    assert!(
        matches!(applied.outcome, ChangeOutcome::Pending(_)),
        "{applied:?}"
    );
}

#[test]
fn a_rollback_checks_the_paths_again_as_they_are_now() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    allow(&engine, &name, "a.example.com");
    // The folder v2 granted now leads into enclos's own files.
    std::fs::remove_dir(&work).unwrap();
    std::os::unix::fs::symlink(&engine.layout.protected()[0], &work).unwrap();
    let file = engine.layout.read_policy("home").unwrap();
    let err = engine
        .policy_rollback(&alice(), &name, 2, Confirm::Yes)
        .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    assert!(err.to_string().contains("cannot be restored"), "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 3);
    assert_eq!(engine.layout.read_policy("home").unwrap(), file);
}

#[test]
fn a_rollback_of_a_sandbox_that_does_not_exist_says_so() {
    let (_dir, engine, _name) = with_sandbox();
    let err = engine
        .policy_rollback(&alice(), &"typo".parse().unwrap(), 2, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
}

#[test]
fn a_rollback_with_yes_restarts_into_it_and_drops_a_change_pending() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    let more = dir.path().join("more");
    std::fs::create_dir_all(&more).unwrap();
    pending_edit(
        &engine,
        &name,
        &format!("\"{work}\""),
        &format!("\"{work}\", \"{}\"", more.display()),
    );
    let v1 = engine.state.policy_version(&name, 1).unwrap().unwrap().1;
    let applied = done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Yes)
            .unwrap(),
    );
    let ChangeOutcome::Restarted(restarted) = &applied.outcome else {
        panic!("{applied:?}")
    };
    assert_eq!(restarted.version.restores, Some(1));
    assert_eq!(restarted.version.version, 3);
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_none());
    assert_eq!(view.snapshot.id, v1.id);
    assert_eq!(
        engine.layout.read_policy("home").unwrap(),
        v1.overrides_text().unwrap()
    );
}

#[test]
fn a_rollback_to_the_policy_already_pending_records_what_it_restores() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    // Back to v1's file by hand-made edit: the same snapshot as v1, pending.
    pending_edit(&engine, &name, &format!("\"{work}\""), "");
    let planned = engine
        .policy_rollback(&alice(), &name, 1, Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert!(
        !plan.changes.iter().any(|c| c.contains("drop the pending")),
        "{plan:?}"
    );
    let applied = done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Ask)
            .unwrap(),
    );
    let ChangeOutcome::Pending(pending) = &applied.outcome else {
        panic!("{applied:?}")
    };
    assert_eq!(pending.restores, Some(1));
}

#[test]
fn a_pending_rollback_stays_one_when_a_destination_joins_it_or_an_install_fails() {
    let (dir, engine, name) = with_sandbox();
    grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Ask)
            .unwrap(),
    );
    allow(&engine, &name, "a.example.com");
    let pending = engine.policy(&name).unwrap().pending.unwrap();
    assert_eq!(pending.0.restores, Some(1));
    assert!(
        pending
            .1
            .policy
            .net
            .allow
            .contains(&"a.example.com".to_owned())
    );
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| engine.resolve_again(lock, &alice(), &name),
        )
        .unwrap();
    assert_eq!(
        engine.policy(&name).unwrap().pending.unwrap().0.restores,
        Some(1)
    );
}

#[test]
fn resolving_again_after_a_failed_install_leaves_an_edit_not_applied_as_it_is() {
    let (dir, engine, name) = with_sandbox();
    grant_v2(&dir, &engine, &name, "work");
    let resolve_again = || {
        engine
            .write(
                &alice(),
                "test",
                None,
                |_| String::new(),
                |lock| engine.resolve_again(lock, &alice(), &name),
            )
            .unwrap()
    };
    let by_hand = |engine: &Engine| {
        let text = engine.layout.read_policy("home").unwrap();
        let edited = text.replace("allow_add = []", "allow_add = [\"hand.example.com\"]");
        engine.layout.write_policy("home", &edited).unwrap();
        edited
    };
    // Nothing pending: the active policy stays, and so does the edit.
    let edited = by_hand(&engine);
    assert_eq!(resolve_again().version, 2);
    assert_eq!(engine.layout.read_policy("home").unwrap(), edited);
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
    engine
        .layout
        .write_policy("home", &edited.replace("\"hand.example.com\"", ""))
        .unwrap();

    // A pending rollback is resolved from its own text, not the edit.
    let _sleeping = running(&engine, &name);
    done(
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Ask)
            .unwrap(),
    );
    let edited = by_hand(&engine);
    resolve_again();
    let (p, pending) = engine.policy(&name).unwrap().pending.unwrap();
    assert_eq!(p.restores, Some(1));
    assert!(
        pending.policy.net.allow.is_empty(),
        "{:?}",
        pending.policy.net
    );
    assert_eq!(engine.layout.read_policy("home").unwrap(), edited);
}

#[test]
fn a_rollback_or_refresh_over_an_edit_not_applied_beside_a_pending_change_is_refused() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    pending_edit(&engine, &name, &format!("\"{work}\""), "");
    let file = format!("{}# a note\n", engine.layout.read_policy("home").unwrap());
    engine.layout.write_policy("home", &file).unwrap();
    for err in [
        engine
            .policy_rollback(&alice(), &name, 1, Confirm::Yes)
            .unwrap_err(),
        engine
            .policy_refresh(&alice(), &name, Confirm::Yes)
            .unwrap_err(),
    ] {
        assert!(matches!(err, Error::PolicyFileEdited { .. }), "{err}");
    }
    assert!(engine.policy(&name).unwrap().pending.is_some());
    assert_eq!(engine.layout.read_policy("home").unwrap(), file);
}

#[test]
fn a_change_made_meanwhile_is_never_undone_by_a_rollback() {
    let (_dir, engine, name) = with_three_versions();
    let err = super::sandbox::while_waiting(
        &engine,
        || engine.policy_rollback(&alice(), &name, 1, Confirm::Yes),
        |other, lock| {
            // Another command's change, made while the rollback waits.
            let text = other
                .layout
                .read_policy("home")
                .unwrap()
                .replace("allow_add = [", "allow_add = [\"c.example.com\", ");
            let snapshot = other.checked_policy(&name, &text).unwrap();
            other
                .store_policy(lock, &alice(), &name, &text, &snapshot, None)
                .unwrap();
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::PolicyChangedMeanwhile { .. }), "{err}");
    let view = engine.policy(&name).unwrap();
    assert!(
        view.snapshot
            .policy
            .net
            .allow
            .contains(&"c.example.com".to_owned())
    );
}

#[test]
fn a_refresh_while_a_change_waits_asks_then_drops_it() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    pending_edit(&engine, &name, &format!("\"{work}\""), "");
    let err = engine
        .policy_refresh(&alice(), &name, Confirm::Ask)
        .unwrap_err();
    assert!(err.to_string().contains("drop the pending policy"), "{err}");
    let planned = engine
        .policy_refresh(&alice(), &name, Confirm::DryRun)
        .unwrap();
    assert!(
        matches!(&planned, Planned::DryRun(p) if p.changes[0].contains("is the policy in force")),
        "{planned:?}"
    );
    let applied = done(
        engine
            .policy_refresh(&alice(), &name, Confirm::Yes)
            .unwrap(),
    );
    assert!(!applied.changed);
    assert!(
        matches!(applied.outcome, ChangeOutcome::InForce { dropped: Some(_) }),
        "{applied:?}"
    );
    assert_eq!(applied.version.version, 2);
    assert!(engine.policy(&name).unwrap().pending.is_none());
    let last = engine.audit(None).unwrap().pop().unwrap();
    let message = last.finished.unwrap().outcome.message;
    assert!(message.contains("dropping pending snapshot"), "{message}");
}

#[test]
fn a_refresh_whose_policy_resolves_the_same_from_newer_inputs_keeps_the_snapshot() {
    let (_dir, engine, name) = with_sandbox();
    // The adapter of an older enclos, with the same destinations.
    let mut older = crate::engine::policy::adapter_layer(RuntimeKind::Hermes);
    older.version = "0.0.1".into();
    with_adapter(&engine, &name, older);
    let before = engine.policy(&name).unwrap();
    let applied = done(
        engine
            .policy_refresh(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(!applied.changed);
    let after = engine.policy(&name).unwrap();
    assert_eq!(after.version.version, before.version.version);
    assert_eq!(after.snapshot.id, before.snapshot.id);
}

#[test]
fn a_dry_run_of_a_rollback_while_sessions_run_says_it_would_wait() {
    let (dir, engine, name) = with_sandbox();
    grant_v2(&dir, &engine, &name, "work");
    let _sleeping = running(&engine, &name);
    let planned = engine
        .policy_rollback(&alice(), &name, 1, Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert!(
        plan.changes[0].contains("as the pending policy"),
        "{plan:?}"
    );
    assert!(engine.policy(&name).unwrap().pending.is_none());
}

#[test]
fn a_diff_from_another_version_compares_the_active_one_unless_asked() {
    let (dir, engine, name) = with_sandbox();
    let work = grant_v2(&dir, &engine, &name, "work");
    allow(&engine, &name, "a.example.com");
    let _sleeping = running(&engine, &name);
    pending_edit(&engine, &name, &format!("\"{work}\""), "");
    let diff = engine.policy_diff(&name, Some(3), None).unwrap();
    assert_eq!((diff.from, diff.to), (3, Side::Pending));
    let diff = engine.policy_diff(&name, Some(1), None).unwrap();
    assert_eq!((diff.from, diff.to), (1, Side::Version(3)));
    let diff = engine.policy_diff(&name, None, Some(1)).unwrap();
    assert_eq!((diff.from, diff.to), (1, Side::Version(1)));
    let err = engine.policy_diff(&name, None, Some(0)).unwrap_err();
    assert!(matches!(err, Error::NoSuchPolicyVersion { .. }), "{err}");
}
