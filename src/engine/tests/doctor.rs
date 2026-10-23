//! `enclos doctor` (design §10): whether the host runs each backend, whether
//! each sandbox's next session can start, and which files its sessions ran
//! under its policy now compiles differently from (ADR 0018).

use std::path::PathBuf;

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, gone_process, put, session_of};
use super::*;
use crate::backend::Probe;
use crate::engine::{Doctor, Drift, LineChange, NextSession, SandboxCheck, Sandboxes};
use crate::model::sandbox::SandboxName;
use crate::model::session::SessionRecord;

fn check_of(doctor: &Doctor, name: &SandboxName) -> SandboxCheck {
    let Sandboxes::Listed(sandboxes) = &doctor.sandboxes else {
        panic!("{doctor:?}");
    };
    sandboxes.iter().find(|s| s.name == *name).unwrap().clone()
}

fn port(engine: &Engine, name: &SandboxName) -> u16 {
    engine.state.get(name).unwrap().unwrap().proxy_port
}

/// The file the active policy compiles to, written as a session start
/// writes it.
fn compiled_now(engine: &Engine, name: &SandboxName) -> PathBuf {
    engine.compile_policy(name, port(engine, name)).unwrap()
}

/// A file this sandbox's policy compiled to under an earlier enclos, named
/// by its own digest: the rules of now, and one this enclos no longer
/// writes.
fn compiled_earlier(engine: &Engine, name: &SandboxName) -> PathBuf {
    let (now, text) = engine.compiled_file(name, port(engine, name)).unwrap();
    let earlier_text = format!("{text}a rule enclos dropped\n");
    let digest = crate::policy::sha256_hex(earlier_text.as_bytes());
    let earlier = now.with_file_name(format!("{}.fake", &digest[..16]));
    std::fs::create_dir_all(earlier.parent().unwrap()).unwrap();
    std::fs::write(&earlier, earlier_text).unwrap();
    earlier
}

/// A session of `name` that ran under `file`.
fn ran_under(
    engine: &Engine,
    name: &SandboxName,
    root: crate::model::session::ProcessRef,
    file: &std::path::Path,
) -> SessionRecord {
    let mut session = session_of(engine, name, root);
    session.compiled = Some(file.display().to_string());
    put(engine, &session);
    session
}

fn ended(engine: &Engine, name: &SandboxName) {
    let lock = engine.state.lock().unwrap();
    let ids: Vec<_> = engine
        .state
        .sessions(name, true)
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    let record = engine.state.get(name).unwrap().unwrap();
    engine.state.end_sessions(&lock, &ids, &record).unwrap();
}

fn changed(check: &SandboxCheck) -> Vec<crate::engine::CompiledChange> {
    check
        .drift
        .iter()
        .filter_map(|d| match d {
            Drift::Changed(c) => Some(c.clone()),
            Drift::NoLongerCompiles { .. } => None,
        })
        .collect()
}

#[test]
fn before_init_the_backends_are_still_checked() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    let doctor = engine.doctor();
    assert_eq!(doctor.backends[0].found, Probe::Available);
    assert!(doctor.backends[0].runs_here());
    assert_eq!(doctor.sandboxes, Sandboxes::NotInitialized);
    assert!(!doctor.has_problems());
}

#[test]
fn a_backend_not_on_this_host_is_not_tried() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "not on this host",
    ))]);
    let doctor = engine.doctor();
    assert_eq!(doctor.backends[0].runs, None);
    assert!(doctor.has_problems());
}

/// A backend that is there and refuses to run a program, as Seatbelt does
/// in a process already in a sandbox, runs no sandbox: nothing is compiled
/// for its sandboxes, and that is said once.
#[test]
fn a_backend_that_refuses_to_run_is_a_problem_and_nothing_is_compiled() {
    let (_dir, engine, name) = super::policy::with_sandbox_on(FakeBackend::refuses_to_run(
        BackendKind::Seatbelt,
        "sandbox_apply: Operation not permitted",
    ));
    let doctor = engine.doctor();
    assert_eq!(
        doctor.backends[0].runs,
        Some(Probe::Unavailable {
            reason: "sandbox_apply: Operation not permitted".into()
        })
    );
    let check = check_of(&doctor, &name);
    assert!(!check.backend_runs);
    assert_eq!(check.next, NextSession::NotChecked);
    assert!(check.unreadable.is_empty(), "{check:?}");
    assert!(doctor.has_problems());
}

#[test]
fn a_sandbox_with_no_session_yet_is_checked_for_its_next_one() {
    let (_dir, engine, name) = with_sandbox();
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 1, .. }),
        "{check:?}"
    );
    assert_eq!(check.last_version, None);
    assert!(check.drift.is_empty());
    assert!(!doctor.has_problems());
}

/// Its next session compiles the active policy, whatever its last one ran:
/// a home gone stops it, though no session ran yet.
#[test]
fn a_next_session_that_cannot_compile_its_policy_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    let doctor = engine.doctor();
    let NextSession::Fails { error } = check_of(&doctor, &name).next else {
        panic!("{doctor:?}");
    };
    assert!(error.contains("home"), "{error}");
    assert!(doctor.has_problems());
}

#[test]
fn a_policy_that_compiles_as_it_did_has_no_drift() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let check = check_of(&engine.doctor(), &name);
    assert_eq!(check.last_version, Some(1));
    assert!(check.drift.is_empty(), "{check:?}");
}

/// The same version compiled to another file than a session ran under: the
/// lines are shown, with the sessions that still run under it.
#[test]
fn a_policy_enclos_now_compiles_differently_is_shown_with_its_lines() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    ran_under(&engine, &name, sleeping.process(), &earlier);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    let [change] = changed(&check).try_into().unwrap();
    assert_eq!(change.version, 1);
    assert_eq!(change.ran, earlier);
    assert_eq!(
        change.now,
        engine.compiled_file(&name, port(&engine, &name)).unwrap().0
    );
    assert!(!change.edited);
    assert_eq!(
        change.lines,
        Some(vec![LineChange::Removed("a rule enclos dropped".into())])
    );
    assert_eq!(change.running, 1);
    // A drift is shown, not a problem.
    assert!(!doctor.has_problems());

    // Once the file it ran under is gone, the change is still named.
    drop(sleeping);
    std::fs::remove_file(&earlier).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert_eq!(change.lines, None);
    assert_eq!(change.running, 0);
}

/// A file whose name, its digest, no longer matches what it holds was
/// changed after it was written: that is said, not an upgrade.
#[test]
fn a_compiled_file_changed_after_it_was_written_is_named_as_such() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, format!("{text}(allow default)\n")).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert!(change.edited);
    assert_eq!(
        change.lines,
        Some(vec![LineChange::Removed("(allow default)".into())])
    );
}

/// The version compared is the session's, not the active one: a change
/// applied since is `policy diff`'s, not a drift.
#[test]
fn a_session_on_an_earlier_version_is_compared_with_that_version() {
    let (dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    ended(&engine, &name);
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let before = engine.layout.read_policy("home").unwrap();
    let after = match before.contains("write_add = []") {
        true => before.replace(
            "write_add = []",
            &format!("write_add = [\"{}\"]", work.display()),
        ),
        false => before.replace(
            "write_add = [",
            &format!("write_add = [\"{}\", ", work.display()),
        ),
    };
    engine
        .policy_edit(&alice(), &name, &before, &after, Confirm::Yes)
        .unwrap();
    let check = check_of(&engine.doctor(), &name);
    assert!(
        matches!(check.next, NextSession::Compiles { version: 2, .. }),
        "{check:?}"
    );
    assert_eq!(check.last_version, Some(1));
    assert!(check.drift.is_empty(), "{check:?}");
}

/// A session still running under an earlier file is shown though a later
/// session ran under the file of now.
#[test]
fn a_running_session_under_an_earlier_file_is_shown_after_a_later_one() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    ran_under(&engine, &name, sleeping.process(), &earlier);
    let file = compiled_now(&engine, &name);
    ran_under(&engine, &name, gone_process(), &file);
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert_eq!(change.ran, earlier);
    assert_eq!(change.running, 1);

    // A gone session is not one that keeps its rules: once nothing of it
    // runs, the later session is the one compared.
    drop(sleeping);
    assert!(check_of(&engine.doctor(), &name).drift.is_empty());
}

#[test]
fn a_session_whose_policy_version_is_not_recorded_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    let file = compiled_now(&engine, &name);
    let mut session = session_of(&engine, &name, gone_process());
    session.version = 99;
    session.compiled = Some(file.display().to_string());
    put(&engine, &session);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(
        check
            .unreadable
            .iter()
            .any(|u| u.contains("policy version 99")),
        "{check:?}"
    );
    assert!(matches!(check.next, NextSession::Compiles { .. }));
    assert!(doctor.has_problems());
}

#[test]
fn a_sandbox_whose_backend_cannot_run_here_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    let lock = engine.state.lock().unwrap();
    let mut record = engine.state.get(&name).unwrap().unwrap();
    record.backend = BackendKind::Bubblewrap;
    engine.state.put(&lock, &record).unwrap();
    drop(lock);
    let doctor = engine.doctor();
    let check = check_of(&doctor, &name);
    assert!(!check.backend_runs);
    assert_eq!(check.next, NextSession::NotChecked);
    assert!(doctor.has_problems());
}

/// An earlier file edited after it was written is named as such, though
/// the policy also compiles to another file now.
#[test]
fn an_earlier_file_changed_after_it_was_written_is_named_as_such() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    ran_under(&engine, &name, gone_process(), &earlier);
    let text = std::fs::read_to_string(&earlier).unwrap();
    std::fs::write(&earlier, format!("{text}(allow default)\n")).unwrap();
    let [change] = changed(&check_of(&engine.doctor(), &name))
        .try_into()
        .unwrap();
    assert!(change.edited, "{change:?}");
    assert_ne!(change.now, change.ran);
}
