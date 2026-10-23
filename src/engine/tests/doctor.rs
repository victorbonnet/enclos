//! `enclos doctor` (design §10): whether the host runs each backend, and
//! which compiled policies enclos now writes differently (ADR 0018).

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, gone_process, put, session_of};
use super::*;
use crate::engine::{CompiledCheck, Doctor, SandboxCheck};
use crate::model::sandbox::SandboxName;

fn check_of(doctor: &Doctor, name: &SandboxName) -> SandboxCheck {
    doctor
        .sandboxes
        .as_ref()
        .unwrap()
        .iter()
        .find(|s| s.name == *name)
        .unwrap()
        .clone()
}

/// A file this sandbox's policy compiled to under an earlier enclos: its
/// rules, and one this enclos no longer writes.
fn compiled_earlier(engine: &Engine, name: &SandboxName) -> std::path::PathBuf {
    let (now, text) = engine.compiled_file(name, 41001).unwrap();
    let earlier = now.with_file_name("earlier.fake");
    std::fs::create_dir_all(earlier.parent().unwrap()).unwrap();
    std::fs::write(&earlier, format!("{text}a rule enclos dropped\n")).unwrap();
    earlier
}

#[test]
fn before_init_the_backends_are_still_checked() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::available(
        BackendKind::Seatbelt,
    ))]);
    let doctor = engine.doctor().unwrap();
    assert_eq!(doctor.backends.len(), 1);
    assert_eq!(doctor.backends[0].runs, crate::backend::Probe::Available);
    assert_eq!(doctor.sandboxes, None);
    assert!(!doctor.has_problems());
}

#[test]
fn no_backend_that_runs_is_a_problem() {
    let (_dir, engine) = engine_with(vec![Box::new(FakeBackend::unavailable(
        BackendKind::Seatbelt,
        "not on this host",
    ))]);
    let doctor = engine.doctor().unwrap();
    assert_eq!(
        doctor.backends[0].runs,
        crate::backend::Probe::Unavailable {
            reason: "not on this host".into()
        }
    );
    assert!(doctor.has_problems());
}

#[test]
fn a_sandbox_with_no_session_yet_has_nothing_to_compare() {
    let (_dir, engine, name) = with_sandbox();
    let doctor = engine.doctor().unwrap();
    assert_eq!(check_of(&doctor, &name).compiled, CompiledCheck::NeverRun);
    assert!(!doctor.has_problems());
}

#[test]
fn a_policy_that_compiles_as_it_did_is_the_same() {
    let (_dir, engine, name) = with_sandbox();
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    let file = engine.compile_policy(&name, port).unwrap();
    let mut session = session_of(&engine, &name, gone_process());
    session.compiled = Some(file.display().to_string());
    put(&engine, &session);
    assert_eq!(
        check_of(&engine.doctor().unwrap(), &name).compiled,
        CompiledCheck::Same { version: 1 }
    );
}

/// The same snapshot compiled to another file than its last session ran
/// under: enclos's own rules changed, and the lines are shown.
#[test]
fn a_policy_enclos_now_compiles_differently_is_shown_with_its_lines() {
    let (_dir, engine, name) = with_sandbox();
    let earlier = compiled_earlier(&engine, &name);
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some(earlier.display().to_string());
    put(&engine, &session);
    let doctor = engine.doctor().unwrap();
    let CompiledCheck::Changed {
        version,
        ran,
        now,
        lines,
        open,
    } = check_of(&doctor, &name).compiled
    else {
        panic!("{doctor:?}");
    };
    assert_eq!(version, 1);
    assert_eq!(ran, earlier);
    let port = engine.state.get(&name).unwrap().unwrap().proxy_port;
    assert_eq!(now, engine.compiled_file(&name, port).unwrap().0);
    let lines = lines.unwrap();
    assert_eq!(lines.removed, ["a rule enclos dropped"]);
    assert!(lines.added.is_empty(), "{lines:?}");
    assert_eq!(open, 1);
    // A change is shown, not a problem.
    assert!(!doctor.has_problems());

    // The file it ran under removed: the change is still named.
    drop(sleeping);
    std::fs::remove_file(&earlier).unwrap();
    let CompiledCheck::Changed { lines, .. } = check_of(&engine.doctor().unwrap(), &name).compiled
    else {
        panic!("not changed");
    };
    assert_eq!(lines, None);
}

#[test]
fn a_policy_that_cannot_compile_is_a_problem() {
    let (_dir, engine, name) = with_sandbox();
    let mut session = session_of(&engine, &name, gone_process());
    session.compiled = Some("/compiled/at-launch.fake".into());
    put(&engine, &session);
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    let doctor = engine.doctor().unwrap();
    assert!(
        matches!(
            check_of(&doctor, &name).compiled,
            CompiledCheck::Fails { .. }
        ),
        "{doctor:?}"
    );
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
    let doctor = engine.doctor().unwrap();
    assert_eq!(check_of(&doctor, &name).backend, BackendKind::Bubblewrap);
    assert!(doctor.has_problems());
}
