//! A sandbox's life: create, connect, stop, show and remove (design §8).

use super::policy::with_sandbox_on;
use super::*;
use crate::backend::Backend;
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
pub(super) fn session_of(engine: &Engine, name: &SandboxName, root: ProcessRef) -> SessionRecord {
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
        cgroup: None,
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
    with_backends(
        engine,
        vec![Box::new(FakeBackend::unavailable(
            BackendKind::Seatbelt,
            "taken away by the test",
        ))],
    )
}

/// Another engine on `engine`'s folder, with these backends.
pub(super) fn with_backends(engine: &Engine, backends: Vec<Box<dyn Backend>>) -> Engine {
    let layout = engine.layout.clone();
    Engine::new(
        layout.clone(),
        Box::new(SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
        )),
        Box::new(JsonlAuditLog::new(layout.audit_log())),
        backends,
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
        plan.changes[1].starts_with("write its policy.toml again from the `assistant` template"),
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
            && message
                .contains("`enclos sandbox create lab --backend seatbelt --template assistant`"),
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
        plan.changes
            .last()
            .is_some_and(|c| c.starts_with(&format!("run `{}` in sandbox home", default_shell()))),
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
        cgroup: None,
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
