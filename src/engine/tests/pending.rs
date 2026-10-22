//! The pending policy (design §7): a change to the rules a running session
//! keeps from its start waits until a restart applies it.

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionId;

/// `policy.toml` as it is, with `from` replaced by `to`.
fn edited(engine: &Engine, from: &str, to: &str) -> (String, String) {
    let before = engine.layout.read_policy("home").unwrap();
    assert!(before.contains(from), "{before}");
    let after = before.replace(from, to);
    (before, after)
}

/// The edit that lets the sandbox write a folder of its own.
fn grant_work(dir: &TempDir, engine: &Engine) -> (String, String, String) {
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = work.display().to_string();
    let (before, after) = edited(
        engine,
        "write_add = []",
        &format!("write_add = [\"{work}\"]"),
    );
    (work, before, after)
}

/// A session running under a compiled policy, as a `connect` records one.
fn running(engine: &Engine, name: &SandboxName) -> (Sleeping, SessionId) {
    let sleeping = Sleeping::new();
    let mut session = session_of(engine, name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    let id = put(engine, &session);
    (sleeping, id)
}

fn commands(engine: &Engine) -> Vec<String> {
    engine
        .audit(None)
        .unwrap()
        .into_iter()
        .map(|e| e.intent.command)
        .collect()
}

#[test]
fn a_change_to_file_rules_applies_at_once_when_no_session_runs() {
    let (dir, engine, name) = with_sandbox();
    let (work, before, after) = grant_work(&dir, &engine);
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed && applied.pending.is_none(), "{applied:?}");
    assert_eq!(applied.version.version, 2);
    let view = engine.policy(&name).unwrap();
    assert!(view.snapshot.policy.fs.write.contains(&work));
    assert!(view.pending.is_none());
    assert_eq!(commands(&engine).last().unwrap(), "policy edit");
}

#[test]
fn a_change_to_file_rules_waits_as_pending_while_a_session_runs() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let pending = applied.pending.expect("pending");
    assert_eq!(applied.version.version, 1);
    assert!(applied.restarted.is_none());

    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1, "the active policy stays");
    assert!(!view.snapshot.policy.fs.write.contains(&work));
    let (shown, snapshot) = view.pending.as_ref().unwrap();
    assert_eq!(shown, &pending);
    assert!(snapshot.policy.fs.write.contains(&work));
    // `policy.toml` holds the change, and `sandbox show` names it.
    assert_eq!(engine.layout.read_policy("home").unwrap(), after);
    let show = engine.show_sandbox(&name).unwrap();
    assert_eq!(show.pending.as_ref(), Some(&pending));
    // Sessions start under the active policy, not the pending one.
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let (_, compiled) = engine.compiled_file(&name, port).unwrap();
    assert!(!compiled.contains(&work), "{compiled}");
}

#[test]
fn a_network_change_while_a_change_is_pending_applies_at_once_and_joins_it() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );

    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    assert!(applied.pending.is_some(), "{applied:?}");
    assert_eq!(applied.version.version, 2);
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.snapshot.policy.net.allow, ["api.example.com"]);
    assert!(!view.snapshot.policy.fs.write.contains(&work));
    let (_, pending) = view.pending.unwrap();
    assert_eq!(pending.policy.net.allow, ["api.example.com"]);
    assert!(pending.policy.fs.write.contains(&work));

    // Allowed in both now: nothing changes.
    let again = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(!again.changed && again.pending.is_some(), "{again:?}");
}

#[test]
fn discard_drops_the_pending_policy_and_keeps_the_file_it_replaces() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    let planned = engine
        .policy_discard(&alice(), &name, Confirm::DryRun)
        .unwrap();
    assert!(
        matches!(planned, Planned::DryRun(ref p) if p.changes.len() == 2),
        "{planned:?}"
    );
    assert!(engine.policy(&name).unwrap().pending.is_some());

    let discarded = done(
        engine
            .policy_discard(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(discarded.pending.is_some());
    assert_eq!(discarded.version.version, 2);
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_none());
    // The file is the active policy's: the network change stays, the grant
    // goes, and what the file held is kept beside it.
    let file = engine.layout.read_policy("home").unwrap();
    assert_eq!(Some(file.as_str()), view.snapshot.overrides_text());
    assert!(
        file.contains("api.example.com") && !file.contains(&work),
        "{file}"
    );
    let kept = std::fs::read_to_string(discarded.kept.unwrap()).unwrap();
    assert!(
        kept.contains(&work) && kept.contains("api.example.com"),
        "{kept}"
    );

    // Nothing left to drop.
    let again = done(
        engine
            .policy_discard(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert_eq!((again.pending, again.kept), (None, None));
    assert_eq!(commands(&engine).last().unwrap(), "policy discard");
}

#[test]
fn discard_puts_back_a_hand_edit_never_applied() {
    let (_dir, engine, name) = with_sandbox();
    let (_, after) = edited(&engine, "allow_add = []", "allow_add = [\"x.example.com\"]");
    engine.layout.write_policy("home", &after).unwrap();
    let discarded = done(
        engine
            .policy_discard(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(discarded.pending.is_none() && discarded.kept.is_some());
    assert!(
        !engine
            .layout
            .read_policy("home")
            .unwrap()
            .contains("x.example.com")
    );
}

#[test]
fn apply_asks_then_restarts_the_sandbox_into_the_pending_policy() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );

    let err = engine
        .policy_apply(&alice(), &name, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    let planned = engine
        .policy_apply(&alice(), &name, Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert!(plan.changes[0].starts_with("stop sandbox home"), "{plan:?}");
    assert!(plan.changes.iter().any(|c| c.contains(&work)), "{plan:?}");
    assert!(engine.policy(&name).unwrap().pending.is_some());

    let restarted = done(engine.policy_apply(&alice(), &name, Confirm::Yes).unwrap());
    assert_eq!(restarted.version.version, 2);
    assert_eq!(restarted.stopped.unwrap().stopped, [id]);
    assert!(restarted.started.is_empty(), "no services were installed");
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_none());
    assert!(view.snapshot.policy.fs.write.contains(&work));
    let commands = commands(&engine);
    assert_eq!(
        commands[commands.len() - 2..],
        ["sandbox stop", "policy apply"]
    );

    let err = engine
        .policy_apply(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    assert!(matches!(err, Error::NoPendingPolicy { .. }), "{err}");
}

#[test]
fn a_change_made_with_yes_restarts_the_sandbox_at_once() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
            .unwrap(),
    );
    assert!(applied.pending.is_none(), "{applied:?}");
    let restarted = applied.restarted.expect("restarted");
    assert_eq!(restarted.stopped.unwrap().stopped, [id]);
    assert_eq!(applied.version.version, 2);
    assert!(
        engine
            .policy(&name)
            .unwrap()
            .snapshot
            .policy
            .fs
            .write
            .contains(&work)
    );
}

#[test]
fn a_network_change_with_yes_leaves_a_change_pending_before_it_pending() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert!(applied.restarted.is_none(), "{applied:?}");
    assert!(applied.pending.is_some());
}

#[test]
fn an_edit_back_to_the_active_policy_drops_the_pending_one() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &after, &before, Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed && applied.pending.is_none(), "{applied:?}");
    assert_eq!(applied.version.version, 1);
    assert!(engine.policy(&name).unwrap().pending.is_none());
}

#[test]
fn an_edit_of_a_file_changed_since_is_refused() {
    let (dir, engine, name) = with_sandbox();
    let (_work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::PolicyFileChanged { .. }), "{err}");
    assert_eq!(engine.policy(&name).unwrap().version.version, 2);
}

#[test]
fn an_edit_the_policy_refuses_changes_nothing() {
    let (_dir, engine, name) = with_sandbox();
    let (before, after) = edited(&engine, "write_add = []", "write_add = [\"~\"]");
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
        .unwrap_err();
    assert_eq!(err.exit_code(), 2, "{err}");
    assert_eq!(engine.layout.read_policy("home").unwrap(), before);
    assert_eq!(engine.policy(&name).unwrap().version.version, 1);
}

#[test]
fn a_dry_run_of_an_edit_says_it_would_wait_and_changes_nothing() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    let planned = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::DryRun)
        .unwrap();
    let Planned::DryRun(plan) = planned else {
        panic!("{planned:?}")
    };
    assert!(plan.changes[0].contains("pending"), "{plan:?}");
    assert!(plan.changes[1].contains(&work), "{plan:?}");
    assert_eq!(engine.layout.read_policy("home").unwrap(), before);
    assert!(engine.policy(&name).unwrap().pending.is_none());
}

#[test]
fn a_runtime_install_is_refused_while_a_change_is_pending() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    let err = engine
        .install_runtime(
            &alice(),
            &name,
            crate::model::runtime::RuntimeKind::Hermes,
            Confirm::DryRun,
        )
        .unwrap_err();
    assert!(matches!(err, Error::PolicyPending { .. }), "{err}");
}

#[test]
fn a_session_gone_after_a_crash_does_not_hold_a_change_back() {
    let (dir, engine, name) = with_sandbox();
    let mut session = session_of(&engine, &name, {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let recorded = crate::lifecycle::process::reference_of_child(&child).unwrap();
        child.wait().unwrap();
        recorded
    });
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);
    let (_work, before, after) = grant_work(&dir, &engine);
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.pending.is_none(), "{applied:?}");
}
