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
    assert_eq!(history.active, 3);
    assert!(history.pending.is_none());
}

#[test]
fn a_diff_compares_the_version_before_by_default_or_the_versions_asked() {
    let (_dir, engine, name) = with_three_versions();
    let diff = engine.policy_diff(&name, None, None).unwrap();
    assert_eq!((diff.from, diff.to), (Side::Version(2), Side::Version(3)));
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
    assert_eq!((diff.from, diff.to), (Side::Version(1), Side::Pending));
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
                let snapshot = engine.checked_policy_with(name, &text, Some(older))?;
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
