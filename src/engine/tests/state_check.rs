//! `state check` and `state repair` (design §11, acceptance step 8): records
//! compared with the host, repaired where that is safe, named otherwise.

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, put, session_of};
use super::*;
use crate::engine::{Finding, Remedy};
use crate::model::sandbox::SandboxState;

fn repairs(found: &[Finding]) -> usize {
    found
        .iter()
        .filter(|f| matches!(f.remedy, Remedy::Repairs(_)))
        .count()
}

fn set_state(engine: &Engine, name: &SandboxName, state: SandboxState) {
    let lock = engine.state.lock().unwrap();
    let mut record = engine.state.get(name).unwrap().unwrap();
    record.state = state;
    engine.state.put(&lock, &record).unwrap();
}

#[test]
fn a_new_sandbox_matches_the_host() {
    let (_dir, engine, name) = with_sandbox();
    assert_eq!(engine.state_check(None).unwrap(), []);
    assert_eq!(engine.state_check(Some(&name)).unwrap(), []);
}

#[test]
fn a_session_left_open_with_nothing_running_is_ended_by_repair() {
    let (_dir, engine, name) = with_sandbox();
    let sleeping = Sleeping::new();
    put(&engine, &session_of(&engine, &name, sleeping.process()));
    set_state(&engine, &name, SandboxState::Running);
    // While it runs, nothing is wrong.
    assert_eq!(engine.state_check(None).unwrap(), []);
    drop(sleeping);
    let found = engine.state_check(None).unwrap();
    assert!(
        found
            .iter()
            .any(|f| f.what.contains("recorded open, and nothing of them runs")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|f| f.what.contains("recorded running")),
        "{found:?}"
    );
    // A dry run changes nothing.
    let Planned::DryRun(plan) = engine
        .state_repair(&alice(), None, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run repaired");
    };
    assert_eq!(plan.changes.len(), 2, "{plan:?}");
    assert_eq!(engine.state_check(None).unwrap().len(), found.len());

    let repaired = done(engine.state_repair(&alice(), None, Confirm::Yes).unwrap());
    assert_eq!(repairs(&repaired), 2, "{repaired:?}");
    assert_eq!(engine.state_check(None).unwrap(), []);
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert_eq!(
        engine.state.get(&name).unwrap().unwrap().state,
        SandboxState::Stopped
    );
    let audit = engine.audit(None).unwrap();
    let last = audit.last().unwrap();
    assert_eq!(last.intent.command, "state repair");
    assert!(
        last.finished
            .as_ref()
            .unwrap()
            .outcome
            .message
            .contains("repaired 2"),
        "{last:?}"
    );
}

#[test]
fn a_lost_policy_file_is_written_again_from_the_policy_in_force() {
    let (_dir, engine, name) = with_sandbox();
    let file = engine.layout.policy_file(name.as_str());
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    let found = engine.state_check(Some(&name)).unwrap();
    assert_eq!(repairs(&found), 1, "{found:?}");
    done(
        engine
            .state_repair(&alice(), Some(&name), Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    assert_eq!(engine.state_check(None).unwrap(), []);
}

#[test]
fn what_enclos_cannot_fix_is_named_and_left() {
    let (_dir, engine, name) = with_sandbox();
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    std::fs::create_dir_all(engine.layout.sandbox_dir("stray")).unwrap();
    let found = engine.state_check(None).unwrap();
    assert!(
        found.iter().all(|f| matches!(f.remedy, Remedy::Manual(_))),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.sandbox == "home" && f.what.contains("home")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.sandbox == "stray" && f.what.contains("no record")),
        "{found:?}"
    );
    // One sandbox's check leaves other folders out.
    assert!(
        !engine
            .state_check(Some(&name))
            .unwrap()
            .iter()
            .any(|f| f.sandbox == "stray")
    );
    let repaired = done(engine.state_repair(&alice(), None, Confirm::Yes).unwrap());
    assert_eq!(repairs(&repaired), 0);
    assert_eq!(engine.state_check(None).unwrap(), found);
}

/// A program run from the sandbox's folder that no session tracks is
/// named, and nothing signals it: this test stops it itself.
#[test]
fn a_process_no_session_tracks_is_named_and_never_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let program = engine.layout.sandbox_home(name.as_str()).join("sleep");
    std::fs::copy("/bin/sleep", &program).unwrap();
    let mut escaped = std::process::Command::new(&program)
        .arg("30")
        .spawn()
        .unwrap();
    let pid = escaped.id();
    let found = engine.state_check(None).unwrap();
    let named = found
        .iter()
        .find(|f| f.what.contains(&format!("process {pid} ")))
        .unwrap_or_else(|| panic!("{found:?}"));
    assert!(matches!(named.remedy, Remedy::Manual(_)), "{named:?}");
    done(engine.state_repair(&alice(), None, Confirm::Yes).unwrap());
    assert!(escaped.try_wait().unwrap().is_none(), "repair stopped it");
    escaped.kill().unwrap();
    escaped.wait().unwrap();
}
