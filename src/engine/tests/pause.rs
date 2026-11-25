//! Engine tests for host pause and resume (`Engine::pause_sandboxes`,
//! `Engine::resume_sandboxes`), covering invariants I13–I16, H2, H8, H12,
//! H15, revision fencing, names-first refusal, and audit entries.

use std::rc::Rc;

use super::*;
use crate::engine::pause_state::{HostPauseWord, NotPausedWhy, derive_sandbox};
use crate::engine::{PauseOutcome, PauseScope, ResumeOutcome, Unit};
use crate::model::audit::AuditResult;
use crate::model::plan::Confirm;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{BackendKind, SandboxName, SandboxState};
use crate::runtime::ServiceName;
use crate::service::fake::FakeServices;

fn sb(name: &str) -> SandboxName {
    name.parse().unwrap()
}

fn setup_engine(fake: &Rc<FakeServices>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("enclos"));
    let engine = reopen_engine(&layout, fake);
    done(engine.init(&alice(), Confirm::Ask).unwrap());
    (dir, engine)
}

fn reopen_engine(layout: &Layout, fake: &Rc<FakeServices>) -> Engine {
    let state = SqliteStateStore::new(
        layout.state_db(),
        layout.state_lock(),
        crate::state::Wait::Command,
    );
    let audit = JsonlAuditLog::new(layout.audit_log());
    Engine::new(
        layout.clone(),
        Box::new(state),
        Box::new(audit),
        vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
    )
    .with_services(Box::new(Rc::clone(fake)))
    .with_downloader(Box::new(LocalFiles))
}

fn create_sandbox(engine: &Engine, name: &str) -> SandboxName {
    let name = sb(name);
    done(
        engine
            .create_sandbox(
                &alice(),
                SandboxSpec {
                    name: name.clone(),
                    backend: BackendKind::Seatbelt,
                    template: "minimal".parse().unwrap(),
                },
                Confirm::Yes,
            )
            .unwrap(),
    );
    name
}

/// Marks a sandbox as having Hermes installed, sets its record state, and
/// optionally seeds its proxy and gateway services in `fake`.
fn seed_sandbox(
    engine: &Engine,
    fake: &Rc<FakeServices>,
    name: &SandboxName,
    state: SandboxState,
    with_services: bool,
) {
    let lock = engine.state.lock().unwrap();
    let mut rec = engine.state.get(name).unwrap().unwrap();
    rec.runtime = Some(RuntimeKind::Hermes);
    rec.state = state;
    engine.state.put(&lock, &rec).unwrap();
    drop(lock);

    if with_services {
        let proxy = engine.label(name, Unit::Proxy).unwrap();
        let gateway = engine
            .label(name, Unit::Runtime(ServiceName::new("gateway")))
            .unwrap();
        fake.seed(proxy.as_str());
        fake.seed(gateway.as_str());
    }
}

#[test]
fn i13_subset_over_services_less_sandboxes_writes_no_record() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let stopped = create_sandbox(&engine, "stopped");
    let created = create_sandbox(&engine, "created");
    seed_sandbox(&engine, &fake, &stopped, SandboxState::Stopped, false);

    let report = engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![stopped.clone(), created.clone()]),
            None,
        )
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes.len(), 2);
    assert!(
        report
            .sandboxes
            .iter()
            .all(|s| s.outcome == PauseOutcome::NothingToPause)
    );
    assert_eq!(report.host.word, HostPauseWord::Running);
    assert_eq!(report.host.revision, 0);
    assert!(engine.state.host_pause().unwrap().is_none());
    assert!(engine.state.sandbox_pauses().unwrap().is_empty());
}

#[test]
fn i14_and_i15_mixed_subset_pause_and_never_paused_while_anything_runs() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let run_a = create_sandbox(&engine, "alpha");
    let stop_b = create_sandbox(&engine, "beta");
    let run_c = create_sandbox(&engine, "gamma");
    seed_sandbox(&engine, &fake, &run_a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &stop_b, SandboxState::Stopped, false);
    seed_sandbox(&engine, &fake, &run_c, SandboxState::Running, true);

    // Subset pause of alpha (running) + beta (stopped), leaving gamma running.
    let report = engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![run_a.clone(), stop_b.clone()]),
            None,
        )
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::Paused);
    assert_eq!(report.sandboxes[1].outcome, PauseOutcome::NothingToPause);

    // I15: gamma still runs, so host is Partly paused naming gamma.
    assert_eq!(report.host.word, HostPauseWord::PartlyPaused);
    assert_eq!(report.host.runs, vec![run_c.clone()]);
    assert!(!report.host.pause_all);

    // I14: beta is a member with empty labels, covered, not paused, why = nothing_to_pause.
    let host_rec = engine.state.host_pause().unwrap().unwrap();
    let row_b = engine.state.sandbox_pause(&stop_b).unwrap().unwrap();
    assert!(row_b.labels.is_empty());
    let derived_b = derive_sandbox(
        Some(&host_rec),
        SandboxPauseInput {
            name: &stop_b,
            state: &SandboxState::Stopped,
            has_runtime_services: false,
            row: Some(&row_b),
        },
    );
    assert!(derived_b.member && derived_b.covered && !derived_b.paused);
    assert_eq!(derived_b.why, Some(NotPausedWhy::NothingToPause));

    // alpha's gateway was stopped, proxy was kept.
    assert!(
        engine
            .installed_runtime_services(&run_a)
            .unwrap()
            .is_empty()
    );
    let proxy_a = engine.label(&run_a, Unit::Proxy).unwrap();
    assert!(engine.installed_labels(&run_a).unwrap().contains(&proxy_a));
    // gamma was untouched.
    assert!(
        !engine
            .installed_runtime_services(&run_c)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn i16_pause_all_then_resume_one_keeps_released_reason_across_reopen() {
    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let layout = Layout::at(dir.path().join("enclos"));
    let a = create_sandbox(&engine, "alpha");
    let b = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &b, SandboxState::Running, true);

    let paused = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert_eq!(paused.host.word, HostPauseWord::Paused);
    assert!(paused.host.pause_all);

    // Resume only alpha: pause_all record stays in force; alpha is released.
    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert_eq!(resumed.sandboxes[0].outcome, ResumeOutcome::Resumed);
    assert_eq!(resumed.host.word, HostPauseWord::PartlyPaused);
    assert_eq!(resumed.host.runs, vec![a.clone()]);

    // Reopen store from disk: alpha's row and released reason survive (I16, H12).
    drop(engine);
    let engine2 = reopen_engine(&layout, &fake);
    let host = engine2.state.host_pause().unwrap().unwrap();
    assert!(host.pause_all);
    let row_a = engine2.state.sandbox_pause(&a).unwrap().unwrap();
    assert!(row_a.released.is_some());
    let derived_a = derive_sandbox(
        Some(&host),
        SandboxPauseInput {
            name: &a,
            state: &SandboxState::Running,
            has_runtime_services: !engine2.installed_runtime_services(&a).unwrap().is_empty(),
            row: Some(&row_a),
        },
    );
    assert!(!derived_a.paused && !derived_a.covered);
    assert_eq!(derived_a.why, Some(NotPausedWhy::Released));
}

#[test]
fn h8_pause_then_sandbox_stop_then_resume_leaves_as_it_was() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    done(engine.stop_sandbox(&alice(), &a, Confirm::Yes).unwrap());

    // After sandbox stop, row still exists, derived is not paused / nothing_to_pause.
    let host = engine.state.host_pause().unwrap().unwrap();
    let row = engine.state.sandbox_pause(&a).unwrap().unwrap();
    let rec = engine.state.get(&a).unwrap().unwrap();
    assert_eq!(rec.state, SandboxState::Stopped);
    let derived = derive_sandbox(
        Some(&host),
        SandboxPauseInput {
            name: &a,
            state: &rec.state,
            has_runtime_services: false,
            row: Some(&row),
        },
    );
    assert!(!derived.paused);
    assert_eq!(derived.why, Some(NotPausedWhy::NothingToPause));

    // Resume leaves it as it was and installs nothing.
    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert_eq!(resumed.sandboxes[0].outcome, ResumeOutcome::LeftAsItWas);
    assert!(engine.installed_runtime_services(&a).unwrap().is_empty());
    assert!(engine.state.host_pause().unwrap().is_none());
}

#[test]
fn h2_and_h12_running_restored_stopped_and_failed_left_and_rows_survive_reopen() {
    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let layout = Layout::at(dir.path().join("enclos"));
    let running = create_sandbox(&engine, "running");
    let stopped = create_sandbox(&engine, "stopped");
    let failed = create_sandbox(&engine, "failed");
    seed_sandbox(&engine, &fake, &running, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &stopped, SandboxState::Stopped, false);
    seed_sandbox(
        &engine,
        &fake,
        &failed,
        SandboxState::Failed {
            reason: "boom".into(),
        },
        false,
    );

    let paused = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert_eq!(paused.host.word, HostPauseWord::Paused);
    assert!(
        engine
            .installed_runtime_services(&running)
            .unwrap()
            .is_empty()
    );

    // Reopen store before resume (H12).
    drop(engine);
    let engine2 = reopen_engine(&layout, &fake);
    assert_eq!(
        engine2.derive_host_pause().unwrap().word,
        HostPauseWord::Paused
    );

    let resumed = engine2
        .resume_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(!resumed.any_failed());
    let by_name = |n: &SandboxName| {
        resumed
            .sandboxes
            .iter()
            .find(|s| &s.sandbox == n)
            .unwrap()
            .outcome
    };
    assert_eq!(by_name(&running), ResumeOutcome::Resumed);
    assert_eq!(by_name(&stopped), ResumeOutcome::LeftAsItWas);
    assert_eq!(by_name(&failed), ResumeOutcome::LeftAsItWas);
    assert!(
        !engine2
            .installed_runtime_services(&running)
            .unwrap()
            .is_empty()
    );
    assert!(
        engine2
            .installed_runtime_services(&stopped)
            .unwrap()
            .is_empty()
    );
    assert!(
        engine2
            .installed_runtime_services(&failed)
            .unwrap()
            .is_empty()
    );
    assert_eq!(resumed.host.word, HostPauseWord::Running);
    assert!(engine2.state.host_pause().unwrap().is_none());
}

#[test]
fn resume_failure_keeps_member_covered_and_host_partly_paused() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();

    // Refuse starting gateway so resume fails.
    *fake.refuse.borrow_mut() = Some(".gateway".into());
    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(resumed.any_failed());
    assert_eq!(resumed.sandboxes[0].outcome, ResumeOutcome::WouldNotStart);
    let err_msg = resumed.sandboxes[0].error.as_deref().unwrap();
    assert!(err_msg.contains("enclos sandbox resume"), "{err_msg}");
    assert!(!err_msg.contains("sandbox start"), "{err_msg}");

    // Member is owed and covered; host is Partly paused naming it; record kept.
    assert_eq!(resumed.host.word, HostPauseWord::PartlyPaused);
    assert_eq!(resumed.host.owed, vec![a.clone()]);
    assert!(engine.state.host_pause().unwrap().is_some());

    // Re-pausing an owed member clears `released` and restores it to paused.
    let repaused = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert_eq!(repaused.sandboxes[0].outcome, PauseOutcome::Paused);
    assert_eq!(repaused.host.word, HostPauseWord::Paused);
    assert!(
        engine
            .state
            .sandbox_pause(&a)
            .unwrap()
            .unwrap()
            .released
            .is_none()
    );

    // Allow start again and resume succeeds, clearing the record.
    *fake.refuse.borrow_mut() = None;
    let ok = engine
        .resume_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(!ok.any_failed());
    assert_eq!(ok.sandboxes[0].outcome, ResumeOutcome::Resumed);
    assert_eq!(ok.host.word, HostPauseWord::Running);
    assert!(engine.state.host_pause().unwrap().is_none());
}

#[test]
fn pause_all_over_stopped_sandboxes_presents_nothing_to_pause() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let s = create_sandbox(&engine, "stopped");
    seed_sandbox(&engine, &fake, &s, SandboxState::Stopped, false);

    let report = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::NothingToPause);
    assert_eq!(report.host.word, HostPauseWord::Paused);
    assert!(report.host.nothing_to_pause_all);
    assert_eq!(
        report.host.summary_line().as_deref(),
        Some("Paused · nothing to pause: every sandbox is already stopped")
    );
    assert!(engine.state.host_pause().unwrap().is_some());
}

#[test]
fn pause_all_over_subset_never_clears_and_covers_sandbox_created_afterwards() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    let b = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &b, SandboxState::Running, true);

    // Start with subset pause on alpha.
    let r1 = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert!(!r1.host.pause_all);

    // Upgrade to --all: sets pause_all = true.
    let r2 = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(r2.host.pause_all);
    assert_eq!(r2.host.word, HostPauseWord::Paused);

    // A sandbox created afterwards has no row yet, but is covered because pause_all = 1.
    let c = create_sandbox(&engine, "gamma");
    let host = engine.state.host_pause().unwrap().unwrap();
    assert!(engine.state.sandbox_pause(&c).unwrap().is_none());
    let derived_c = derive_sandbox(
        Some(&host),
        SandboxPauseInput {
            name: &c,
            state: &SandboxState::Created,
            has_runtime_services: false,
            row: None,
        },
    );
    assert!(derived_c.covered);
    assert_eq!(derived_c.why, Some(NotPausedWhy::NothingToPause));

    // Subset pause on alpha again never clears pause_all.
    let r3 = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert!(r3.host.pause_all);
    assert_eq!(r3.sandboxes[0].outcome, PauseOutcome::Paused);
}

#[test]
fn names_first_refusal_and_revision_fence_change_nothing() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    let b = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &b, SandboxState::Running, true);

    // Unknown name in the middle refuses the whole request.
    let err = engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![a.clone(), sb("gone"), b.clone()]),
            None,
        )
        .unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
    assert!(engine.state.host_pause().unwrap().is_none());
    assert!(!engine.installed_runtime_services(&a).unwrap().is_empty());
    assert!(!engine.installed_runtime_services(&b).unwrap().is_empty());

    // Wrong expected_revision refuses with PauseConflict and changes nothing.
    let err = engine
        .pause_sandboxes(&alice(), PauseScope::All, Some(999))
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::PauseConflict {
                expected: 999,
                found: 0
            }
        ),
        "{err}"
    );
    assert!(engine.state.host_pause().unwrap().is_none());
    assert!(!engine.installed_runtime_services(&a).unwrap().is_empty());

    // Matching expected_revision = 0 succeeds.
    let ok = engine
        .pause_sandboxes(&alice(), PauseScope::All, Some(0))
        .unwrap();
    let rev = ok.host.revision;
    assert!(rev > 0);

    // Stale expected_revision on resume refuses and changes nothing.
    let err = engine
        .resume_sandboxes(&alice(), PauseScope::All, Some(rev - 1))
        .unwrap_err();
    assert!(matches!(err, Error::PauseConflict { .. }), "{err}");
    assert_eq!(
        engine.derive_host_pause().unwrap().word,
        HostPauseWord::Paused
    );
}

#[test]
fn audit_entries_and_sandbox_rm_on_paused_sandbox() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();

    // Audit log has a finished `sandbox pause` entry naming the actor and scope.
    let entries = engine.audit(None).unwrap();
    let pause_entry = entries
        .iter()
        .find(|e| e.intent.command == "sandbox pause")
        .expect("sandbox pause audit entry");
    assert_eq!(pause_entry.intent.by, alice());
    assert_eq!(pause_entry.intent.target.as_deref(), Some("all"));
    assert_eq!(
        pause_entry.finished.as_ref().unwrap().outcome.result,
        AuditResult::Ok
    );
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());

    // Stop then remove the paused sandbox: cascade removes its sandbox_pauses row,
    // and a later `resume --all` succeeds cleanly.
    done(engine.stop_sandbox(&alice(), &a, Confirm::Yes).unwrap());
    done(
        engine
            .remove_sandbox(&alice(), &a, false, Confirm::Yes)
            .unwrap(),
    );
    assert!(engine.state.sandbox_pauses().unwrap().is_empty());

    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(!resumed.any_failed());
    assert!(resumed.sandboxes.is_empty());
    assert!(engine.state.host_pause().unwrap().is_none());
}

#[test]
fn state_check_is_quiet_for_a_paused_sandbox() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();

    // H3: state check must not report the paused gateway as missing or the
    // running sandbox as drifted.
    let findings = engine.state_check(Some(&a)).unwrap();
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn status_and_views_present_paused_state_and_unreadable_record() {
    use crate::engine::HostPauseRead;

    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    let b = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &b, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();

    // SandboxView & StatusView agree on derived pause state.
    let view_a = engine.show_sandbox(&a).unwrap();
    assert!(view_a.paused);
    assert_eq!(view_a.pause_why, None);
    let view_b = engine.show_sandbox(&b).unwrap();
    assert!(!view_b.paused);
    assert_eq!(view_b.pause_why, Some(NotPausedWhy::NotCovered));

    let status = engine.status(None).unwrap();
    assert!(matches!(
        &status.pause,
        HostPauseRead::Readable(h) if h.word == HostPauseWord::PartlyPaused && h.runs == vec![b.clone()]
    ));
    let st_a = status.sandboxes.iter().find(|s| s.name == a).unwrap();
    assert!(st_a.paused);
    assert_eq!(st_a.pause_why, None);
    let st_b = status.sandboxes.iter().find(|s| s.name == b).unwrap();
    assert!(!st_b.paused);
    assert_eq!(st_b.pause_why, Some(NotPausedWhy::NotCovered));

    // Corrupt the host_pause row so it cannot be read: status still prints
    // sandboxes and reports pause state as Unreadable (never Running).
    let conn = rusqlite::Connection::open(dir.path().join("enclos/state.db")).unwrap();
    conn.execute("UPDATE host_pause SET pause_all = 99 WHERE id = 1", [])
        .unwrap();
    drop(conn);

    let unreadable = engine.status(None).unwrap();
    assert_eq!(unreadable.sandboxes.len(), 2);
    assert!(
        matches!(&unreadable.pause, HostPauseRead::Unreadable(msg) if msg.contains("pause_all")),
        "{:?}",
        unreadable.pause
    );
    let json_val = serde_json::to_value(&unreadable.pause).unwrap();
    assert_eq!(json_val["state"], "unreadable");
    assert!(json_val["error"].as_str().unwrap().contains("pause_all"));
}
