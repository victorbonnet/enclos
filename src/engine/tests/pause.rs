//! Engine tests for host pause and resume (`Engine::pause_sandboxes`,
//! `Engine::resume_sandboxes`), covering invariants I13–I16, H2, H8, H12,
//! H15, revision fencing, names-first refusal, and audit entries.

use std::rc::Rc;

use super::*;
use crate::engine::pause_state::{
    HostPauseRead, HostPauseView, HostPauseWord, NotPausedWhy, SandboxPauseRead, derive_sandbox,
};
use crate::engine::{PauseOutcome, PauseScope, ResumeOutcome, Unit};
use crate::model::audit::AuditResult;
use crate::model::plan::Confirm;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::{BackendKind, SandboxName, SandboxState};
use crate::runtime::ServiceName;
use crate::service::fake::FakeServices;

fn readable_host(read: &HostPauseRead) -> &HostPauseView {
    match read {
        HostPauseRead::Readable(v) => v,
        HostPauseRead::Unreadable(why) => panic!("expected readable host pause, got: {why}"),
    }
}

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
    assert_eq!(readable_host(&report.host).word, HostPauseWord::Running);
    assert_eq!(readable_host(&report.host).revision, 0);
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
    assert_eq!(
        readable_host(&report.host).word,
        HostPauseWord::PartlyPaused
    );
    assert_eq!(readable_host(&report.host).runs, vec![run_c.clone()]);
    assert!(!readable_host(&report.host).pause_all);

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
    assert_eq!(readable_host(&paused.host).word, HostPauseWord::Paused);
    assert!(readable_host(&paused.host).pause_all);

    // Resume only alpha: pause_all record stays in force; alpha is released.
    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert_eq!(resumed.sandboxes[0].outcome, ResumeOutcome::Resumed);
    assert_eq!(
        readable_host(&resumed.host).word,
        HostPauseWord::PartlyPaused
    );
    assert_eq!(readable_host(&resumed.host).runs, vec![a.clone()]);

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
    assert_eq!(readable_host(&paused.host).word, HostPauseWord::Paused);
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
    assert_eq!(readable_host(&resumed.host).word, HostPauseWord::Running);
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
    assert_eq!(
        readable_host(&resumed.host).word,
        HostPauseWord::PartlyPaused
    );
    assert_eq!(readable_host(&resumed.host).owed, vec![a.clone()]);
    assert!(engine.state.host_pause().unwrap().is_some());

    // Re-pausing an owed member clears `released` and restores it to paused.
    let repaused = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert_eq!(repaused.sandboxes[0].outcome, PauseOutcome::Paused);
    assert_eq!(readable_host(&repaused.host).word, HostPauseWord::Paused);
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
    assert_eq!(readable_host(&ok.host).word, HostPauseWord::Running);
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
    assert_eq!(readable_host(&report.host).word, HostPauseWord::Paused);
    assert!(readable_host(&report.host).nothing_to_pause_all);
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
    assert!(!readable_host(&r1.host).pause_all);

    // Upgrade to --all: sets pause_all = true.
    let r2 = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(readable_host(&r2.host).pause_all);
    assert_eq!(readable_host(&r2.host).word, HostPauseWord::Paused);

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
    assert!(readable_host(&r3.host).pause_all);
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
    let rev = readable_host(&ok.host).revision;
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
    assert_eq!(
        view_a.pause,
        SandboxPauseRead::Readable {
            paused: true,
            why: None
        }
    );
    let view_b = engine.show_sandbox(&b).unwrap();
    assert_eq!(
        view_b.pause,
        SandboxPauseRead::Readable {
            paused: false,
            why: Some(NotPausedWhy::NotCovered)
        }
    );

    let status = engine.status(None).unwrap();
    assert!(matches!(
        &status.pause,
        HostPauseRead::Readable(h) if h.word == HostPauseWord::PartlyPaused && h.runs == vec![b.clone()]
    ));
    let st_a = status.sandboxes.iter().find(|s| s.name == a).unwrap();
    assert_eq!(
        st_a.pause,
        SandboxPauseRead::Readable {
            paused: true,
            why: None
        }
    );
    let st_b = status.sandboxes.iter().find(|s| s.name == b).unwrap();
    assert_eq!(
        st_b.pause,
        SandboxPauseRead::Readable {
            paused: false,
            why: Some(NotPausedWhy::NotCovered)
        }
    );

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

#[test]
fn subset_pause_while_in_force_adds_stopped_sandbox_and_clears_released() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let grid = create_sandbox(&engine, "grid");
    let lab = create_sandbox(&engine, "lab");
    seed_sandbox(&engine, &fake, &grid, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &lab, SandboxState::Stopped, false);

    // Pause running `grid`: host record comes into force.
    let r1 = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![grid.clone()]), None)
        .unwrap();
    assert_eq!(r1.sandboxes[0].outcome, PauseOutcome::Paused);
    assert!(engine.state.sandbox_pause(&lab).unwrap().is_none());

    // Pause stopped `lab` while record is in force: membership grows, `lab`
    // gets an empty row and reads covered, not paused, why = nothing_to_pause.
    let r2 = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert_eq!(r2.sandboxes[0].outcome, PauseOutcome::NothingToPause);
    let host = engine.state.host_pause().unwrap().unwrap();
    let row_lab = engine.state.sandbox_pause(&lab).unwrap().unwrap();
    assert!(row_lab.labels.is_empty());
    assert!(row_lab.released.is_none());
    let derived_lab = derive_sandbox(
        Some(&host),
        SandboxPauseInput {
            name: &lab,
            state: &SandboxState::Stopped,
            has_runtime_services: false,
            row: Some(&row_lab),
        },
    );
    assert!(derived_lab.member && derived_lab.covered && !derived_lab.paused);
    assert_eq!(derived_lab.why, Some(NotPausedWhy::NothingToPause));

    // Resume `lab` (sets `released`), keep `grid` paused so host record stays
    // in force, then pause stopped `lab` again: `released` is cleared.
    engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert!(
        engine
            .state
            .sandbox_pause(&lab)
            .unwrap()
            .unwrap()
            .released
            .is_some()
    );
    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert!(
        engine
            .state
            .sandbox_pause(&lab)
            .unwrap()
            .unwrap()
            .released
            .is_none()
    );

    // Also test a released member that HAS labels and is now stopped:
    // resume `grid` with failure -> stop `grid` -> pause `grid` -> `released`
    // cleared and labels kept!
    *fake.refuse.borrow_mut() = Some(".gateway".into());
    engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![grid.clone()]), None)
        .unwrap();
    *fake.refuse.borrow_mut() = None;
    done(engine.stop_sandbox(&alice(), &grid, Confirm::Yes).unwrap());
    let before = engine.state.sandbox_pause(&grid).unwrap().unwrap();
    assert!(before.released.is_some());
    assert!(!before.labels.is_empty());

    let r3 = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![grid.clone()]), None)
        .unwrap();
    assert_eq!(r3.sandboxes[0].outcome, PauseOutcome::NothingToPause);
    let after = engine.state.sandbox_pause(&grid).unwrap().unwrap();
    assert!(after.released.is_none());
    assert_eq!(after.labels, before.labels);
}

#[test]
fn owed_member_stays_covered_when_stopped_and_keeps_record_on_other_resume() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let grid = create_sandbox(&engine, "grid");
    let lab = create_sandbox(&engine, "lab");
    seed_sandbox(&engine, &fake, &grid, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &lab, SandboxState::Running, true);

    // Subset pause (pause_all = 0) of grid and lab.
    engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![grid.clone(), lab.clone()]),
            None,
        )
        .unwrap();

    // Make `resume grid` fail so grid is owed.
    *fake.refuse.borrow_mut() = Some("grid.gateway".into());
    let r = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![grid.clone()]), None)
        .unwrap();
    assert_eq!(r.sandboxes[0].outcome, ResumeOutcome::WouldNotStart);
    *fake.refuse.borrow_mut() = None;

    // Stop grid: per answers §5, grid is STILL covered and owed with why = would_not_start.
    done(engine.stop_sandbox(&alice(), &grid, Confirm::Yes).unwrap());
    let snap = engine.pause_state_snapshot().unwrap();
    let grid_entry = snap.sandboxes.iter().find(|s| s.sandbox == grid).unwrap();
    assert!(grid_entry.view.owed);
    assert!(grid_entry.view.covered);
    assert!(!grid_entry.view.paused);
    assert_eq!(grid_entry.view.why, Some(NotPausedWhy::WouldNotStart));

    // A later `resume lab` (with pause_all = 0) must NOT delete the host record
    // because grid is still owed.
    let r2 = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert_eq!(r2.sandboxes[0].outcome, ResumeOutcome::Resumed);
    assert!(engine.state.host_pause().unwrap().is_some());
    assert_eq!(readable_host(&r2.host).word, HostPauseWord::PartlyPaused);
    assert_eq!(readable_host(&r2.host).owed, vec![grid]);
}

#[test]
fn h11_would_not_stop_keeps_row_names_it_and_host_reads_partly_paused() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    let b = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &b, SandboxState::Running, true);

    *fake.refuse_stop.borrow_mut() = Some("beta.gateway".into());
    let report = engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();
    assert!(report.any_failed());
    let res_a = report.sandboxes.iter().find(|s| s.sandbox == a).unwrap();
    let res_b = report.sandboxes.iter().find(|s| s.sandbox == b).unwrap();
    assert_eq!(res_a.outcome, PauseOutcome::Paused);
    assert_eq!(res_b.outcome, PauseOutcome::WouldNotStop);
    assert!(res_b.error.is_some());

    // beta keeps its row, host reads Partly paused naming beta.
    assert!(engine.state.sandbox_pause(&b).unwrap().is_some());
    let host = readable_host(&report.host);
    assert_eq!(host.word, HostPauseWord::PartlyPaused);
    assert_eq!(host.runs, vec![b.clone()]);

    // Audit entry closed as failed naming beta, no unfinished entry.
    let entries = engine.audit(None).unwrap();
    let pause_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox pause")
        .unwrap();
    assert_eq!(
        pause_entry.finished.as_ref().unwrap().outcome.result,
        AuditResult::Failed
    );
    assert!(
        pause_entry
            .finished
            .as_ref()
            .unwrap()
            .outcome
            .message
            .contains("beta")
    );
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());
}

#[test]
fn error_after_audit_begin_finishes_audit_entry_as_failed_for_pause_and_resume() {
    // 1. Resume: inject an `installed_runtime_services` error after `audit.begin`.
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);
    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();

    *fake.refuse_installed.borrow_mut() = true;
    assert!(
        engine
            .resume_sandboxes(&alice(), PauseScope::All, None)
            .is_err()
    );
    *fake.refuse_installed.borrow_mut() = false;

    let entries = engine.audit(None).unwrap();
    let resume_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox resume")
        .expect("resume audit entry");
    assert_eq!(
        resume_entry.finished.as_ref().unwrap().outcome.result,
        AuditResult::Failed
    );
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());

    // 2. Pause: drop `sandbox_pauses` table after planning? Planning reads
    // `sandbox_pauses`, so instead drop a trigger/check or make `begin_pause`
    // fail via a SQLite trigger that aborts INSERT into `host_pause`!
    let fake2 = Rc::new(FakeServices::default());
    let (dir2, engine2) = setup_engine(&fake2);
    let b = create_sandbox(&engine2, "beta");
    seed_sandbox(&engine2, &fake2, &b, SandboxState::Running, true);

    let conn = rusqlite::Connection::open(dir2.path().join("enclos/state.db")).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER abort_host_pause BEFORE INSERT ON host_pause
         BEGIN SELECT RAISE(ABORT, 'injected host_pause failure'); END;",
    )
    .unwrap();
    drop(conn);

    assert!(
        engine2
            .pause_sandboxes(&alice(), PauseScope::All, None)
            .is_err()
    );
    let entries2 = engine2.audit(None).unwrap();
    let pause_entry = entries2
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox pause")
        .expect("pause audit entry");
    assert_eq!(
        pause_entry.finished.as_ref().unwrap().outcome.result,
        AuditResult::Failed
    );
    assert!(engine2.verify_audit().unwrap().unfinished.is_empty());
}

#[test]
fn failed_host_read_after_work_still_returns_sandbox_report() {
    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    // Corrupt `host_pause` during `on_stop`, after rows are written and
    // service stops, so the post-work `read_host_pause` fails.
    let db_path = dir.path().join("enclos/state.db");
    *fake.on_stop.borrow_mut() = Some(Box::new(move |_| {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("UPDATE host_pause SET pause_all = 99 WHERE id = 1", [])
            .unwrap();
    }));

    let report = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![a.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert!(report.host_unreadable());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, a);
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::Paused);
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());
}

#[test]
fn unreadable_sandbox_pause_record_is_reported_never_not_paused() {
    use crate::engine::Remedy;

    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let a = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &a, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::All, None)
        .unwrap();

    // Corrupt `sandbox_pauses.labels` on disk with invalid JSON.
    let conn = rusqlite::Connection::open(dir.path().join("enclos/state.db")).unwrap();
    conn.execute(
        "UPDATE sandbox_pauses SET labels = 'not-json' WHERE sandbox = 'alpha'",
        [],
    )
    .unwrap();
    drop(conn);

    // 1. `state check` reports unreadable pause record, does NOT flag paused
    //    gateway as missing, and does NOT offer RecordStopped repair.
    let findings = engine.state_check(Some(&a)).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.what.contains("pause record cannot be read")),
        "expected unreadable finding, got: {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.what.contains("gateway")),
        "paused gateway must not be flagged missing: {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f.remedy, Remedy::Repairs(_))),
        "must not offer automatic repair on unreadable pause record: {findings:?}"
    );

    // 2. `sandbox show` reports `SandboxPauseRead::Unreadable`, never `paused: false`.
    let view = engine.show_sandbox(&a).unwrap();
    assert!(
        matches!(&view.pause, SandboxPauseRead::Unreadable(why) if why.contains("labels")),
        "{:?}",
        view.pause
    );

    // 3. `status` reports `SandboxPauseRead::Unreadable` and serialises `"paused": null`
    //    with `"pause_unreadable"`, never `"paused": false`.
    let status = engine.status(None).unwrap();
    let st_a = status.sandboxes.iter().find(|s| s.name == a).unwrap();
    assert!(
        matches!(&st_a.pause, SandboxPauseRead::Unreadable(why) if why.contains("labels")),
        "{:?}",
        st_a.pause
    );
    let json_val = serde_json::to_value(st_a).unwrap();
    assert_eq!(json_val["paused"], serde_json::Value::Null);
    assert!(
        json_val["pause_unreadable"]
            .as_str()
            .unwrap()
            .contains("labels")
    );
}

#[test]
fn resume_post_work_cleanup_failure_returns_report_and_finishes_audit_failed() {
    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let grid = create_sandbox(&engine, "grid");
    let lab = create_sandbox(&engine, "lab");
    seed_sandbox(&engine, &fake, &grid, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &lab, SandboxState::Running, true);

    engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![grid.clone(), lab.clone()]),
            None,
        )
        .unwrap();

    // Corrupt `lab`'s pause row so post-work `sandbox_pauses()` fails while
    // `resume grid` is cleaning up records after installing `grid`'s service.
    let db_path = dir.path().join("enclos/state.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE sandbox_pauses SET labels = 'not-json' WHERE sandbox = 'lab'",
        [],
    )
    .unwrap();
    drop(conn);

    let report = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![grid.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert!(report.host_unreadable());
    assert!(report.cleanup_failed());
    assert!(report.cleanup_error.is_some());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, grid);
    assert_eq!(report.sandboxes[0].outcome, ResumeOutcome::Resumed);

    // Audit entry must be finished `failed`, naming both the resumed service
    // and the clean-up failure, with no unfinished entries left behind.
    let entries = engine.audit(None).unwrap();
    let resume_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox resume")
        .expect("resume audit entry");
    let finished = resume_entry.finished.as_ref().expect("finished audit");
    assert_eq!(finished.outcome.result, AuditResult::Failed);
    assert!(
        finished.outcome.message.contains("resumed grid"),
        "expected resumed sandbox in audit message, got: {}",
        finished.outcome.message
    );
    assert!(
        finished.outcome.message.contains("clean-up"),
        "expected clean-up note in audit message, got: {}",
        finished.outcome.message
    );
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());

    // `lab`'s row and `host_pause` are left untouched.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let (lab_labels, lab_released): (String, Option<String>) = conn
        .query_row(
            "SELECT labels, released FROM sandbox_pauses WHERE sandbox = 'lab'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(lab_labels, "not-json");
    assert!(lab_released.is_none());
    let host_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM host_pause", [], |r| r.get(0))
        .unwrap();
    assert_eq!(host_count, 1);
}

#[test]
fn pause_and_resume_audit_subjects_are_deduplicated() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let lab = create_sandbox(&engine, "lab");
    let grid = create_sandbox(&engine, "grid");
    seed_sandbox(&engine, &fake, &lab, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &grid, SandboxState::Running, true);

    engine
        .pause_sandboxes(
            &alice(),
            PauseScope::Names(vec![lab.clone(), grid.clone(), lab.clone()]),
            None,
        )
        .unwrap();
    engine
        .resume_sandboxes(
            &alice(),
            PauseScope::Names(vec![lab.clone(), grid.clone(), lab.clone()]),
            None,
        )
        .unwrap();

    let entries = engine.audit(None).unwrap();
    let pause_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox pause")
        .expect("pause audit entry");
    let resume_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox resume")
        .expect("resume audit entry");
    assert_eq!(pause_entry.intent.target.as_deref(), Some("lab, grid"));
    assert_eq!(resume_entry.intent.target.as_deref(), Some("lab, grid"));
}

#[test]
fn resume_cleanup_failure_over_readable_record_reads_running_and_surfaces_error() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);

    // Subset pause (pause_all = false) on alpha, then stop alpha while paused.
    let paused = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert_eq!(readable_host(&paused.host).word, HostPauseWord::Paused);

    done(engine.stop_sandbox(&alice(), &alpha, Confirm::Yes).unwrap());

    // Inject a clean-up failure while host_pause and sandbox_pauses stay
    // completely readable (the silent clean-up failure case).
    crate::engine::pause::test_hooks::fail_next_cleanup_with(crate::error::Error::State(
        crate::state::StateError::Locked {
            path: std::path::PathBuf::from("state.lock"),
        },
    ));

    let report = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert!(!report.host_unreadable());
    assert!(report.cleanup_failed());
    assert!(report.cleanup_error.is_some());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, alpha);
    assert_eq!(report.sandboxes[0].outcome, ResumeOutcome::LeftAsItWas);

    // Host must NOT read plain Paused when pause_all = false and nothing is
    // covered; it reads Running while keeping the record's non-zero revision.
    let host = readable_host(&report.host);
    assert_eq!(host.word, HostPauseWord::Running);
    assert_ne!(host.revision, 0);
    assert_eq!(host.since, None);
    assert_eq!(host.by, None);
    assert!(!report.host.in_force());

    // Audit entry is closed `failed` naming the clean-up failure.
    let entries = engine.audit(None).unwrap();
    let resume_entry = entries
        .iter()
        .rev()
        .find(|e| e.intent.command == "sandbox resume")
        .expect("resume audit entry");
    let finished = resume_entry.finished.as_ref().expect("finished audit");
    assert_eq!(finished.outcome.result, AuditResult::Failed);
    assert!(
        finished.outcome.message.contains("clean-up"),
        "expected clean-up note in audit message, got: {}",
        finished.outcome.message
    );
    assert!(engine.verify_audit().unwrap().unfinished.is_empty());

    // Re-running resume with the reported revision cleans up the lingering record.
    let rerun = engine
        .resume_sandboxes(
            &alice(),
            PauseScope::Names(vec![alpha]),
            Some(host.revision),
        )
        .unwrap();
    assert!(!rerun.cleanup_failed());
    let host_after = readable_host(&rerun.host);
    assert_eq!(host_after.word, HostPauseWord::Running);
    assert_eq!(host_after.revision, 0);
}

#[test]
fn resume_cleanup_retries_lock_and_surfaces_lock_error_as_cleanup_error() {
    use std::cell::Cell;

    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();

    // 1. Exhausted lock retries in finish_resume_records surface as
    //    `cleanup_error` on `Ok(ResumeReport)`, not as `Err` from `resume_sandboxes`.
    let calls = Rc::new(Cell::new(0usize));
    let calls_ref = Rc::clone(&calls);
    crate::engine::pause::test_hooks::set_next_cleanup_lock_hook(2, move || {
        calls_ref.set(calls_ref.get() + 1);
        Err(crate::state::StateError::Locked {
            path: std::path::PathBuf::from("state.lock"),
        })
    });

    let report = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert_eq!(calls.get(), 2, "clean-up lock must retry boundedly");
    assert!(!report.any_failed());
    assert!(report.cleanup_failed());
    assert!(report.cleanup_error.is_some());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].outcome, ResumeOutcome::Resumed);
    let rev = readable_host(&report.host).revision;
    assert_ne!(rev, 0);

    // 2. Transient lock failures succeed on retry and delete the record.
    let retry_calls = Rc::new(Cell::new(0usize));
    let retry_ref = Rc::clone(&retry_calls);
    crate::engine::pause::test_hooks::set_next_cleanup_lock_hook(3, move || {
        let n = retry_ref.get() + 1;
        retry_ref.set(n);
        if n < 3 {
            Err(crate::state::StateError::Locked {
                path: std::path::PathBuf::from("state.lock"),
            })
        } else {
            Ok(())
        }
    });

    let rerun = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![alpha]), Some(rev))
        .unwrap();
    assert_eq!(retry_calls.get(), 3);
    assert!(!rerun.cleanup_failed());
    assert_eq!(readable_host(&rerun.host).revision, 0);
}

#[test]
fn i13_subset_pause_after_dead_record_writes_nothing_and_keeps_running() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    let lab = create_sandbox(&engine, "lab");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &lab, SandboxState::Stopped, false);

    // Pause alpha, then stop and remove it: cascade deletes alpha's row while
    // `host_pause` lingers as a dead record (pause_all = false, nothing covered).
    let first = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert_eq!(readable_host(&first.host).word, HostPauseWord::Paused);
    let dead_rev = readable_host(&first.host).revision;
    assert_ne!(dead_rev, 0);

    done(engine.stop_sandbox(&alice(), &alpha, Confirm::Yes).unwrap());
    done(
        engine
            .remove_sandbox(&alice(), &alpha, false, Confirm::Yes)
            .unwrap(),
    );

    // Host now derives Running with the lingering record's revision.
    let before = engine.derive_host_pause().unwrap();
    assert_eq!(before.word, HostPauseWord::Running);
    assert_eq!(before.revision, dead_rev);

    // I13: pausing `lab` (no services) must write nothing and leave host Running.
    let report = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, lab);
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::NothingToPause);
    assert!(
        engine.state.sandbox_pause(&lab).unwrap().is_none(),
        "must not write an empty sandbox_pauses row for lab"
    );
    let after = readable_host(&report.host);
    assert_eq!(after.word, HostPauseWord::Running);
    assert_eq!(after.revision, dead_rev);
    assert_eq!(
        engine.state.host_pause().unwrap().unwrap().revision,
        dead_rev
    );
}

#[test]
fn subset_pause_supersedes_dead_record_with_fresh_actor_and_since() {
    let fake = Rc::new(FakeServices::default());
    let (dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    let beta = create_sandbox(&engine, "beta");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &beta, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    done(engine.stop_sandbox(&alice(), &alpha, Confirm::Yes).unwrap());
    done(
        engine
            .remove_sandbox(&alice(), &alpha, false, Confirm::Yes)
            .unwrap(),
    );

    // Backdate the dead record's timestamp so the fresh pause's `since` is
    // deterministically distinct even within the same millisecond.
    let old_at = "2026-01-01T00:00:00Z";
    let conn = rusqlite::Connection::open(dir.path().join("enclos/state.db")).unwrap();
    conn.execute("UPDATE host_pause SET at = ?1 WHERE id = 1", [old_at])
        .unwrap();
    drop(conn);

    let dead = engine.state.host_pause().unwrap().unwrap();
    assert_eq!(dead.by, alice());
    assert_eq!(dead.at.to_string(), old_at);
    assert_eq!(
        engine.derive_host_pause().unwrap().word,
        HostPauseWord::Running
    );

    let bob = crate::model::audit::Actor {
        user: "bob".into(),
        host: "linux".into(),
    };
    let report = engine
        .pause_sandboxes(&bob, PauseScope::Names(vec![beta.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, beta);
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::Paused);

    let host = readable_host(&report.host);
    assert_eq!(host.word, HostPauseWord::Paused);
    assert!(report.host.in_force());
    assert!(host.revision > dead.revision);
    assert_eq!(host.by.as_ref(), Some(&bob));
    assert_ne!(host.since.map(|t| t.to_string()).as_deref(), Some(old_at));
    assert!(host.since.is_some());
}

#[test]
fn i13_subset_pause_after_cleanup_failure_writes_nothing_and_keeps_running() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);

    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    done(engine.stop_sandbox(&alice(), &alpha, Confirm::Yes).unwrap());

    crate::engine::pause::test_hooks::fail_next_cleanup_with(crate::error::Error::State(
        crate::state::StateError::Locked {
            path: std::path::PathBuf::from("state.lock"),
        },
    ));
    let resumed = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert!(resumed.cleanup_failed());
    let lingering = readable_host(&resumed.host);
    assert_eq!(lingering.word, HostPauseWord::Running);
    assert_ne!(lingering.revision, 0);

    // Pausing alpha (which now has no services) over the lingering clean-up-failed
    // record must write nothing and keep the host Running at the same revision.
    let report = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes.len(), 1);
    assert_eq!(report.sandboxes[0].sandbox, alpha);
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::NothingToPause);

    let after = readable_host(&report.host);
    assert_eq!(after.word, HostPauseWord::Running);
    assert_eq!(after.revision, lingering.revision);
    assert!(
        engine
            .state
            .sandbox_pause(&alpha)
            .unwrap()
            .unwrap()
            .released
            .is_some(),
        "lingering released row must not have been cleared"
    );
}

#[test]
fn i13_subset_pause_after_start_of_only_owed_member_writes_nothing_and_keeps_running() {
    let fake = Rc::new(FakeServices::default());
    let (_dir, engine) = setup_engine(&fake);
    let alpha = create_sandbox(&engine, "alpha");
    let lab = create_sandbox(&engine, "lab");
    seed_sandbox(&engine, &fake, &alpha, SandboxState::Running, true);
    seed_sandbox(&engine, &fake, &lab, SandboxState::Stopped, false);

    engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();

    // Make `resume alpha` fail so alpha is owed (still covered).
    *fake.refuse.borrow_mut() = Some("alpha.gateway".into());
    let r = engine
        .resume_sandboxes(&alice(), PauseScope::Names(vec![alpha.clone()]), None)
        .unwrap();
    assert_eq!(r.sandboxes[0].outcome, ResumeOutcome::WouldNotStart);
    *fake.refuse.borrow_mut() = None;
    assert_eq!(
        readable_host(&r.host).word,
        HostPauseWord::PartlyPaused,
        "an owed member keeps the pause in force"
    );

    // `sandbox start` of the only owed member releases it; the record lingers
    // and the host reads Running.
    engine.start_sandbox(&alice(), &alpha).unwrap();
    let lingering = engine.derive_host_pause().unwrap();
    assert_eq!(lingering.word, HostPauseWord::Running);
    assert_ne!(lingering.revision, 0);

    // I13: pausing an empty sandbox must write nothing and keep the host Running.
    let report = engine
        .pause_sandboxes(&alice(), PauseScope::Names(vec![lab.clone()]), None)
        .unwrap();
    assert!(!report.any_failed());
    assert_eq!(report.sandboxes[0].outcome, PauseOutcome::NothingToPause);
    assert!(engine.state.sandbox_pause(&lab).unwrap().is_none());
    let after = readable_host(&report.host);
    assert_eq!(after.word, HostPauseWord::Running);
    assert_eq!(after.revision, lingering.revision);
}
