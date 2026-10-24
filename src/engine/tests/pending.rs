//! The pending policy (design §7): a change to the rules a running session
//! keeps from its start waits until a restart applies it.

use std::rc::Rc;

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::engine::ChangeOutcome;
use crate::model::policy::{NetMode, PendingPolicy};
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::service::fake::FakeServices;

/// `policy.toml` as it is, with `from` replaced by `to`.
fn edited(engine: &Engine, from: &str, to: &str) -> (String, String) {
    let before = engine.layout.read_policy("home").unwrap();
    assert!(before.contains(from), "{before}");
    let after = before.replace(from, to);
    (before, after)
}

/// The edit that lets the sandbox write `folder` too.
fn grant(dir: &TempDir, engine: &Engine, folder: &str) -> (String, String, String) {
    let work = dir.path().join(folder);
    std::fs::create_dir_all(&work).unwrap();
    let work = work.display().to_string();
    let before = engine.layout.read_policy("home").unwrap();
    let after = match before.contains("write_add = []") {
        true => before.replace("write_add = []", &format!("write_add = [\"{work}\"]")),
        false => before.replace("write_add = [", &format!("write_add = [\"{work}\", ")),
    };
    assert_ne!(before, after);
    (work, before, after)
}

fn grant_work(dir: &TempDir, engine: &Engine) -> (String, String, String) {
    grant(dir, engine, "work")
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

fn pending_of(applied: &crate::engine::PolicyApplied) -> Option<&PendingPolicy> {
    match &applied.outcome {
        ChangeOutcome::Pending(p) => Some(p),
        _ => None,
    }
}

/// Makes `after` the pending policy, while a session runs.
fn make_pending(engine: &Engine, name: &SandboxName, before: &str, after: &str) -> PendingPolicy {
    let applied = done(
        engine
            .policy_edit(&alice(), name, before, after, Confirm::Ask)
            .unwrap(),
    );
    pending_of(&applied).expect("pending").clone()
}

fn writes(engine: &Engine, name: &SandboxName, path: &str) -> bool {
    engine
        .policy(name)
        .unwrap()
        .snapshot
        .policy
        .fs
        .write
        .iter()
        .any(|w| w == path)
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
    assert!(applied.changed, "{applied:?}");
    assert_eq!(applied.outcome, ChangeOutcome::InForce { dropped: None });
    assert_eq!(applied.version.version, 2);
    assert!(writes(&engine, &name, &work));
    assert!(engine.policy(&name).unwrap().pending.is_none());
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
    let pending = pending_of(&applied).expect("pending").clone();
    assert!(!applied.changed);
    assert_eq!(applied.version.version, 1);

    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1, "the active policy stays");
    assert!(!writes(&engine, &name, &work));
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
    make_pending(&engine, &name, &before, &after);

    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed);
    assert!(pending_of(&applied).is_some(), "{applied:?}");
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
    assert!(!again.changed && pending_of(&again).is_some(), "{again:?}");
}

#[test]
fn a_network_only_edit_while_a_change_is_pending_applies_at_once_too() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);

    // Tighten the network in the edit: the proxy must enforce it at once.
    let narrowed = after.replace("[network]", "[network]\nmode = \"allowlist\"");
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &after, &narrowed, Confirm::Ask)
            .unwrap(),
    );
    assert!(applied.changed, "{applied:?}");
    assert_eq!(applied.version.version, 2);
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.snapshot.policy.net.mode, NetMode::Allowlist);
    assert!(!view.snapshot.policy.fs.write.contains(&work));
    let (_, pending) = view.pending.unwrap();
    assert_eq!(pending.policy.net.mode, NetMode::Allowlist);
    assert!(pending.policy.fs.write.contains(&work));
}

#[test]
fn an_edit_that_also_changes_file_rules_while_pending_waits_as_a_whole() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    let (_more, _, more) = grant(&dir, &engine, "more");
    let mixed = more.replace("[network]", "[network]\nmode = \"allowlist\"");
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &after, &mixed, Confirm::Ask)
            .unwrap(),
    );
    assert!(
        !applied.changed && pending_of(&applied).is_some(),
        "{applied:?}"
    );
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1);
    assert_eq!(view.snapshot.policy.net.mode, NetMode::Public);
}

#[test]
fn discard_drops_the_pending_policy_and_keeps_the_file_it_replaces() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
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
    // goes, and what the file held is kept beside it, for its owner only.
    let file = engine.layout.read_policy("home").unwrap();
    assert_eq!(Some(file.as_str()), view.snapshot.overrides_text());
    assert!(
        file.contains("api.example.com") && !file.contains(&work),
        "{file}"
    );
    let kept_path = discarded.kept.unwrap();
    let kept = std::fs::read_to_string(&kept_path).unwrap();
    assert!(
        kept.contains(&work) && kept.contains("api.example.com"),
        "{kept}"
    );
    let mode = std::fs::metadata(&kept_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

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
    let file = engine.layout.read_policy("home").unwrap();
    assert!(!file.contains("x.example.com"), "{file}");
}

#[test]
fn discard_drops_a_pending_policy_whose_file_was_put_back_by_hand() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    engine.layout.write_policy("home", &before).unwrap();
    let discarded = done(
        engine
            .policy_discard(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    assert!(discarded.pending.is_some());
    assert_eq!(discarded.kept, None, "the file held nothing else");
    let kept = engine
        .layout
        .policy_file("home")
        .with_file_name("policy.toml.discarded");
    assert!(!kept.exists());
    assert!(engine.policy(&name).unwrap().pending.is_none());
}

#[test]
fn discard_also_drops_an_edit_policy_edit_kept() {
    let (_dir, engine, name) = with_sandbox();
    let files = engine.edit_files(&name);
    std::fs::write(&files.copy, "kept edit").unwrap();
    std::fs::write(&files.base, "base").unwrap();
    let discarded = done(
        engine
            .policy_discard(&alice(), &name, Confirm::Ask)
            .unwrap(),
    );
    let moved = discarded.edit.unwrap();
    assert_eq!(std::fs::read_to_string(moved).unwrap(), "kept edit");
    assert!(!files.copy.exists() && !files.base.exists());
}

/// Empties the text the active snapshot keeps, as for one stored before
/// snapshots kept their `policy.toml`.
fn forget_active_text(engine: &Engine, name: &SandboxName) {
    let id = engine.policy(name).unwrap().snapshot.id;
    let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
    conn.execute(
        "UPDATE policy_snapshots SET overrides = '' WHERE id = ?1",
        [&id.0],
    )
    .unwrap();
}

#[test]
fn without_the_active_policys_text_discard_changes_nothing_and_says_why() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    forget_active_text(&engine, &name);
    for confirm in [Confirm::DryRun, Confirm::Ask] {
        let err = engine.policy_discard(&alice(), &name, confirm).unwrap_err();
        assert!(matches!(err, Error::PolicyTextUnknown { .. }), "{err}");
    }
    assert!(engine.policy(&name).unwrap().pending.is_some());
    assert_eq!(engine.layout.read_policy("home").unwrap(), after);
}

#[test]
fn without_the_active_policys_text_a_destination_waits_and_is_not_said_in_force() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    forget_active_text(&engine, &name);
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .unwrap(),
    );
    assert!(!applied.changed, "{applied:?}");
    assert!(pending_of(&applied).is_some());
    let view = engine.policy(&name).unwrap();
    assert!(view.snapshot.policy.net.allow.is_empty());
    assert_eq!(
        view.pending.unwrap().1.policy.net.allow,
        ["api.example.com"]
    );
}

#[test]
fn apply_asks_then_restarts_the_sandbox_into_the_pending_policy() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);

    let err = engine
        .policy_apply(&alice(), &name, Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(err.to_string().contains("ends 1 session "), "{err}");
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
    assert!(engine.policy(&name).unwrap().pending.is_none());
    assert!(writes(&engine, &name, &work));
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
fn apply_after_the_sessions_ended_asks_nothing() {
    let (dir, engine, name) = with_sandbox();
    let (sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    drop(sleeping);
    let restarted = done(engine.policy_apply(&alice(), &name, Confirm::Ask).unwrap());
    assert_eq!(restarted.version.version, 2);
    // The stop records the end of the session gone.
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert!(writes(&engine, &name, &work));
}

/// A sandbox `home` whose services a fake service manager installed.
fn with_services() -> (TempDir, Engine, Rc<FakeServices>, SandboxName) {
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
    engine.start_sandbox(&alice(), &name).unwrap();
    (dir, engine, fake, name)
}

#[test]
fn apply_stops_the_services_then_starts_them_under_the_pending_policy() {
    let (dir, engine, fake, name) = with_services();
    let installed = engine.service_labels(&name).unwrap();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    fake.stopped.borrow_mut().clear();

    let restarted = done(engine.policy_apply(&alice(), &name, Confirm::Yes).unwrap());
    assert_eq!(restarted.stopped.as_ref().unwrap().services, installed);
    assert_eq!(restarted.started, installed);
    assert_eq!(*fake.stopped.borrow(), installed);
    assert!(writes(&engine, &name, &work));
    let commands = commands(&engine);
    let apply = commands.iter().rposition(|c| c == "policy apply").unwrap();
    assert!(commands[..apply].contains(&"sandbox stop".to_owned()));
    assert!(commands[apply..].contains(&"sandbox start".to_owned()));
}

#[test]
fn a_failed_start_after_apply_says_the_policy_is_active_and_how_to_start_again() {
    let (dir, engine, fake, name) = with_services();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    *fake.refuse.borrow_mut() = Some("proxy".into());
    let err = engine
        .policy_apply(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    let Error::FailedAfter { done, .. } = &err else {
        panic!("{err}")
    };
    assert!(done.contains("policy v2 active"), "{done}");
    assert!(
        err.to_string().contains("enclos sandbox start home"),
        "{err}"
    );
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 2);
    assert!(view.pending.is_none());
}

#[test]
fn processes_that_survive_the_stop_keep_the_policy_pending_and_name_the_services_removed() {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    let (dir, engine, _fake, name) = with_services();
    // A program in a group made for it, which leaves a sleep there and
    // exits once its input closes: the sleep is only counted, so the stop
    // cannot end it.
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
        compiled: Some("/compiled/at-launch.sb".into()),
        root: crate::lifecycle::process::reference(program.id())
            .unwrap()
            .unwrap(),
        pgid: Some(program.id()),
        tracked: Vec::new(),
        started_at: crate::model::now(),
        ended_at: None,
    };
    put(&engine, &session);
    let start = std::time::Instant::now();
    let sleep = loop {
        let view = engine.show_sandbox(&name).unwrap();
        let found = view
            .sessions
            .iter()
            .flat_map(|s| &s.members)
            .find(|m| m.pid != program.id())
            .cloned();
        if let Some(m) = found {
            break m;
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    program.stdin.take().unwrap().write_all(b"\n").unwrap();
    program.wait().unwrap();

    let err = engine
        .policy_apply(&alice(), &name, Confirm::Yes)
        .unwrap_err();
    // The test ends the sleep it started, whatever the result.
    let sleep = crate::model::session::ProcessRef {
        pid: sleep.pid,
        started: sleep.started,
    };
    crate::lifecycle::process::signal_process(&sleep, crate::lifecycle::process::Signal::Kill)
        .unwrap();
    let text = err.to_string();
    assert!(text.contains("stays pending"), "{text}");
    assert!(text.contains("removed its services"), "{text}");
    assert!(text.contains("enclos sandbox start home"), "{text}");
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_some());
    assert_eq!(view.version.version, 1);
    assert!(matches!(
        engine.show_sandbox(&name).unwrap().record.state,
        SandboxState::Failed { .. }
    ));
    assert!(!commands(&engine).contains(&"policy apply".to_owned()));
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
    let ChangeOutcome::Restarted(restarted) = &applied.outcome else {
        panic!("{applied:?}")
    };
    assert_eq!(restarted.stopped.as_ref().unwrap().stopped, [id]);
    assert!(applied.changed);
    assert_eq!(applied.version.version, 2);
    assert!(writes(&engine, &name, &work));
}

#[test]
fn a_restart_with_yes_that_fails_says_the_change_was_saved_as_pending() {
    let (dir, engine, fake, name) = with_services();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    *fake.refuse_stop.borrow_mut() = Some("proxy".into());
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("saving the change as the pending policy"),
        "{err}"
    );
    assert!(engine.policy(&name).unwrap().pending.is_some());
    assert_eq!(engine.layout.read_policy("home").unwrap(), after);
}

#[test]
fn allow_with_yes_restarts_for_the_file_rules_it_brings() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, id) = running(&engine, &name);
    let (work, _, after) = grant_work(&dir, &engine);
    engine.layout.write_policy("home", &after).unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    let ChangeOutcome::Restarted(restarted) = &applied.outcome else {
        panic!("{applied:?}")
    };
    assert_eq!(restarted.stopped.as_ref().unwrap().stopped, [id]);
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_none());
    assert!(view.snapshot.policy.fs.write.contains(&work));
    assert_eq!(view.snapshot.policy.net.allow, ["api.example.com"]);
}

#[test]
fn a_network_change_with_yes_leaves_a_change_pending_before_it_pending() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert!(pending_of(&applied).is_some(), "{applied:?}");
}

#[test]
fn allow_once_the_sessions_ended_asks_before_putting_the_pending_change_in_force() {
    let (dir, engine, name) = with_sandbox();
    let (sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    drop(sleeping);
    let err = engine
        .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
        .unwrap_err();
    assert!(matches!(err, Error::NeedsConfirmation { .. }), "{err}");
    assert!(err.to_string().contains(&work), "{err}");
    let applied = done(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Yes)
            .unwrap(),
    );
    assert!(
        matches!(applied.outcome, ChangeOutcome::InForce { dropped: Some(_) }),
        "{applied:?}"
    );
    assert!(engine.policy(&name).unwrap().pending.is_none());
    assert!(writes(&engine, &name, &work));
}

#[test]
fn an_edit_back_to_the_active_policy_drops_the_pending_one() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    let applied = done(
        engine
            .policy_edit(&alice(), &name, &after, &before, Confirm::Ask)
            .unwrap(),
    );
    assert!(
        matches!(applied.outcome, ChangeOutcome::InForce { dropped: Some(_) }),
        "{applied:?}"
    );
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

/// Makes every write of a pending policy fail, as a full disk would.
fn refuse_pending(engine: &Engine) {
    let conn = rusqlite::Connection::open(engine.layout.state_db()).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER refuse_pending BEFORE INSERT ON pending_policies
         BEGIN SELECT RAISE(ABORT, 'refused by the test'); END;",
    )
    .unwrap();
}

#[test]
fn a_pending_policy_that_cannot_be_saved_leaves_the_file_and_the_versions_as_they_were() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    refuse_pending(&engine);
    assert!(
        engine
            .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
            .is_err()
    );
    assert_eq!(engine.layout.read_policy("home").unwrap(), before);
    let view = engine.policy(&name).unwrap();
    assert!(view.pending.is_none());
    assert_eq!(view.version.version, 1);
}

#[test]
fn a_network_change_whose_pending_part_cannot_be_saved_is_not_in_force_either() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    refuse_pending(&engine);
    assert!(
        engine
            .policy_allow(&alice(), &name, "api.example.com", Confirm::Ask)
            .is_err()
    );
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1);
    assert!(view.snapshot.policy.net.allow.is_empty());
    assert_eq!(engine.layout.read_policy("home").unwrap(), after);
}

#[test]
fn applying_a_pending_policy_replaced_since_is_refused() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    let first = make_pending(&engine, &name, &before, &after);
    let (_more, _, more) = grant(&dir, &engine, "more");
    make_pending(&engine, &name, &after, &more);
    let err = engine.restart_into(&alice(), &name, &first).unwrap_err();
    let Error::FailedAfter { error, done } = &err else {
        panic!("{err}")
    };
    assert!(matches!(**error, Error::PendingChanged { .. }), "{err}");
    assert!(done.starts_with("stopping sandbox home"), "{done}");
    let view = engine.policy(&name).unwrap();
    assert_eq!(view.version.version, 1);
    assert_ne!(view.pending.unwrap().0, first);
}

#[test]
fn resolving_again_after_a_failed_install_keeps_a_pending_change_pending() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
    let version = engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| engine.resolve_again(lock, &alice(), &name),
        )
        .unwrap();
    assert_eq!(version.version, 1);
    assert!(!writes(&engine, &name, &work));
    let pending = engine.policy(&name).unwrap().pending.unwrap().1;
    assert!(pending.policy.fs.write.contains(&work));
}

#[test]
fn a_runtime_install_is_refused_while_a_change_is_pending() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    make_pending(&engine, &name, &before, &after);
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
    assert!(pending_of(&applied).is_none(), "{applied:?}");
}

#[test]
fn a_change_made_while_a_runtime_installed_gets_its_destinations_once_it_is_recorded() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    // Made while the installer ran: resolved without the runtime.
    make_pending(&engine, &name, &before, &after);
    engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| {
                let mut record = engine.state.get(&name)?.unwrap();
                record.runtime = Some(crate::model::runtime::RuntimeKind::Hermes);
                engine.state.put(lock, &record)?;
                engine.resolve_with_runtime(lock, &alice(), &name)
            },
        )
        .unwrap();
    let view = engine.policy(&name).unwrap();
    let hermes = "chatgpt.com".to_owned();
    assert!(view.snapshot.policy.net.allow.contains(&hermes));
    assert!(view.pending.unwrap().1.policy.net.allow.contains(&hermes));
}

#[test]
fn a_restart_with_yes_whose_start_fails_says_the_change_is_in_force_not_pending() {
    let (dir, engine, fake, name) = with_services();
    let (_sleeping, _id) = running(&engine, &name);
    let (work, before, after) = grant_work(&dir, &engine);
    *fake.refuse.borrow_mut() = Some("proxy".into());
    let err = engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains("as the pending policy"), "{text}");
    assert!(text.contains("policy v2 active"), "{text}");
    assert!(engine.policy(&name).unwrap().pending.is_none());
    assert!(writes(&engine, &name, &work));
}

#[test]
fn what_allow_lists_is_what_goes_in_force_when_the_file_no_longer_waits() {
    let (dir, engine, name) = with_sandbox();
    let (_sleeping, _id) = running(&engine, &name);
    let (_work, before, after) = grant_work(&dir, &engine);
    // A change mixing a write grant and a destination waits as a whole.
    let mixed = after.replace("allow_add = []", "allow_add = [\"b.example.com\"]");
    make_pending(&engine, &name, &before, &mixed);
    // The grant is taken out by hand: what is left goes in force at once,
    // the destination included, so it is listed against the active policy.
    let by_hand = before.replace("allow_add = []", "allow_add = [\"b.example.com\"]");
    engine.layout.write_policy("home", &by_hand).unwrap();
    let err = engine
        .policy_allow(&alice(), &name, "c.example.com", Confirm::Ask)
        .unwrap_err();
    assert!(err.to_string().contains("allow b.example.com"), "{err}");
}
