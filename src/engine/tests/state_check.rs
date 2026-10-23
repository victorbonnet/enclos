//! `state check` and `state repair` (design §11): records compared with the
//! host, repaired where that is safe, named otherwise. No test signals a
//! process it did not start.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, gone_process, put, session_of, while_waiting};
use super::services::{hermes_with_services, sandbox_with_services};
use super::*;
use crate::engine::service::Unit;
use crate::engine::{Finding, Remedy, Subject};
use crate::model::sandbox::{SandboxName, SandboxState};
use crate::model::session::ProcessRef;

fn repairs(found: &[Finding]) -> Vec<String> {
    found
        .iter()
        .filter_map(|f| match &f.remedy {
            Remedy::Repairs(repair) => Some(repair.to_string()),
            _ => None,
        })
        .collect()
}

fn about<'a>(found: &'a [Finding], text: &str) -> Vec<&'a Finding> {
    found.iter().filter(|f| f.what.contains(text)).collect()
}

fn set_state(engine: &Engine, name: &SandboxName, state: SandboxState) {
    let lock = engine.state.lock().unwrap();
    let mut record = engine.state.get(name).unwrap().unwrap();
    record.state = state;
    engine.state.put(&lock, &record).unwrap();
}

fn state_of(engine: &Engine, name: &SandboxName) -> SandboxState {
    engine.state.get(name).unwrap().unwrap().state
}

fn repair(engine: &Engine, only: Option<&SandboxName>) -> Vec<Finding> {
    done(engine.state_repair(&alice(), only, Confirm::Yes).unwrap())
}

fn last_summary(engine: &Engine) -> String {
    let audit = engine.audit(None).unwrap();
    let last = audit.last().unwrap();
    assert_eq!(last.intent.command, "state repair");
    last.finished.as_ref().unwrap().outcome.message.clone()
}

/// A program of the sandbox's that sleeps: a copy of this test program in
/// its home, started from there by a relative path, as `PATH` would, so that
/// `ps` lists it as `./sleeper`, running only [`sleeps_when_asked`]. A copy
/// of `/bin/sleep` would not do: macOS kills a copied platform program as
/// it runs. Ended and reaped when dropped; this test's own child.
struct FromHome(std::process::Child);

const SLEEP: &str = "ENCLOS_TEST_SLEEP";

impl FromHome {
    fn new(home: &Path) -> FromHome {
        std::fs::copy(std::env::current_exe().unwrap(), home.join("sleeper")).unwrap();
        let child = std::process::Command::new("./sleeper")
            .args([
                "--exact",
                "engine::tests::state_check::sleeps_when_asked",
                "--test-threads=1",
            ])
            .env(SLEEP, "1")
            .current_dir(home)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut started = FromHome(child);
        // Running, and past its start: listed with its own program file.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(started.runs(), "the sleeper exited at once");
        started
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn process(&self) -> ProcessRef {
        crate::lifecycle::process::reference(self.pid())
            .unwrap()
            .unwrap()
    }

    fn runs(&mut self) -> bool {
        self.0.try_wait().unwrap().is_none()
    }
}

/// What [`FromHome`] runs: sleeps when asked to, passes at once otherwise.
#[test]
fn sleeps_when_asked() {
    if std::env::var_os(SLEEP).is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

impl Drop for FromHome {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_new_sandbox_matches_the_host() {
    let (_dir, engine, name) = with_sandbox();
    assert_eq!(engine.state_check(None).unwrap(), []);
    assert_eq!(engine.state_check(Some(&name)).unwrap(), []);
    assert_eq!(repair(&engine, None), []);
    assert_eq!(last_summary(&engine), "nothing to repair");
}

#[test]
fn a_gone_session_is_ended_and_the_sandbox_recorded_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let sleeping = Sleeping::new();
    let id = put(&engine, &session_of(&engine, &name, sleeping.process()));
    set_state(&engine, &name, SandboxState::Running);
    // While it runs, nothing is wrong.
    assert_eq!(engine.state_check(None).unwrap(), []);
    drop(sleeping);
    let found = engine.state_check(None).unwrap();
    assert_eq!(
        about(&found, &format!("session {id} is gone, and recorded open")).len(),
        1,
        "{found:?}"
    );
    assert_eq!(
        about(&found, "recorded running, and nothing of it runs").len(),
        1
    );
    // A dry run changes nothing and records nothing.
    let entries = engine.audit(None).unwrap().len();
    let Planned::DryRun(plan) = engine
        .state_repair(&alice(), None, Confirm::DryRun)
        .unwrap()
    else {
        panic!("a dry run repaired");
    };
    assert_eq!(
        plan.changes,
        [
            "record its end (sandbox home)",
            "record it stopped (sandbox home)"
        ]
    );
    assert_eq!(engine.state_check(None).unwrap(), found);
    assert_eq!(engine.audit(None).unwrap().len(), entries);

    let repaired = repair(&engine, None);
    assert_eq!(repairs(&repaired), ["record its end", "record it stopped"]);
    assert_eq!(engine.state_check(None).unwrap(), []);
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
    assert_eq!(last_summary(&engine), "repaired 2, left 0 for a person");
}

#[test]
fn a_sandbox_recorded_running_with_nothing_of_it_is_recorded_stopped() {
    let (_dir, engine, name) = with_sandbox();
    set_state(&engine, &name, SandboxState::Running);
    assert_eq!(repairs(&repair(&engine, None)), ["record it stopped"]);
    assert_eq!(state_of(&engine, &name), SandboxState::Stopped);
}

#[test]
fn only_the_gone_session_is_ended_while_another_runs() {
    let (_dir, engine, name) = with_sandbox();
    let sleeping = Sleeping::new();
    let live = put(&engine, &session_of(&engine, &name, sleeping.process()));
    let gone = put(&engine, &session_of(&engine, &name, gone_process()));
    set_state(&engine, &name, SandboxState::Running);
    let found = engine.state_check(None).unwrap();
    assert_eq!(repairs(&found), ["record its end"], "{found:?}");
    repair(&engine, None);
    let open: Vec<_> = engine
        .state
        .sessions(&name, true)
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(open, [live]);
    assert_ne!(live, gone);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}

#[test]
fn a_failed_sandbox_keeps_its_state_when_its_gone_sessions_end() {
    let (_dir, engine, name) = with_sandbox();
    put(&engine, &session_of(&engine, &name, gone_process()));
    let failed = SandboxState::Failed {
        reason: "the proxy exited".into(),
    };
    set_state(&engine, &name, failed.clone());
    assert_eq!(repairs(&repair(&engine, None)), ["record its end"]);
    assert_eq!(state_of(&engine, &name), failed);
}

/// Repair acts on what it finds under the lock, not on what was found
/// before: a session started meanwhile keeps the sandbox running.
#[test]
fn repair_looks_again_under_the_lock() {
    let (_dir, engine, name) = with_sandbox();
    let gone = put(&engine, &session_of(&engine, &name, gone_process()));
    set_state(&engine, &name, SandboxState::Running);
    assert_eq!(
        repairs(&engine.state_check(None).unwrap()),
        ["record its end", "record it stopped"]
    );
    let sleeping = Sleeping::new();
    let started = session_of(&engine, &name, sleeping.process());
    let repaired = while_waiting(
        &engine,
        || repair(&engine, None),
        |other, lock| {
            other.state.put_session(lock, &started).unwrap();
        },
    );
    assert_eq!(repairs(&repaired), ["record its end"]);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
    let open = engine.state.sessions(&name, true).unwrap();
    assert!(open.iter().all(|s| s.id != gone), "{open:?}");
    assert_eq!(open.len(), 1);
}

#[test]
fn a_lost_policy_file_is_written_again_from_the_active_policy() {
    let (_dir, engine, name) = with_sandbox();
    let file = engine.layout.policy_file(name.as_str());
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    let found = engine.state_check(Some(&name)).unwrap();
    assert_eq!(
        repairs(&found),
        ["write policy.toml again from the text its active policy was resolved from"]
    );
    repair(&engine, Some(&name));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(engine.state_check(None).unwrap(), []);
}

/// While a change waits, `policy.toml` holds the pending policy's text, and
/// that is what comes back.
#[test]
fn a_lost_policy_file_comes_back_with_the_pending_change() {
    let (dir, engine, name) = with_sandbox();
    let sleeping = Sleeping::new();
    let mut session = session_of(&engine, &name, sleeping.process());
    session.compiled = Some("/compiled/at-launch.sb".into());
    put(&engine, &session);
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
        .policy_edit(&alice(), &name, &before, &after, Confirm::Ask)
        .unwrap();
    assert!(engine.state.pending_policy(&name).unwrap().is_some());
    let file = engine.layout.policy_file(name.as_str());
    std::fs::remove_file(&file).unwrap();
    assert_eq!(
        repairs(&repair(&engine, Some(&name))),
        ["write policy.toml again from the text its pending policy was resolved from"]
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), after);
}

#[test]
fn what_enclos_cannot_fix_is_named_and_left() {
    let (_dir, engine, name) = with_sandbox();
    std::fs::remove_dir_all(engine.layout.sandbox_home(name.as_str())).unwrap();
    std::fs::create_dir_all(engine.layout.sandbox_dir("stray")).unwrap();
    std::fs::create_dir_all(engine.layout.sandbox_dir("odd.bak\x1b[2J")).unwrap();
    let found = engine.state_check(None).unwrap();
    assert!(found.iter().all(|f| f.remedy.is_left()), "{found:?}");
    let home = about(&found, "its home");
    assert_eq!(home.len(), 1, "{found:?}");
    assert_eq!(home[0].subject, Subject::Sandbox(name.clone()));
    let stray = about(&found, "stray has no record");
    assert_eq!(stray[0].subject, Subject::Folder("stray".into()));
    assert!(
        matches!(&stray[0].remedy, Remedy::Manual(m) if m.contains("sandbox create stray")),
        "{stray:?}"
    );
    // A folder whose name is not a sandbox's is named escaped, and nothing
    // tells to create a sandbox by that name.
    let odd = about(&found, "odd.bak");
    assert_eq!(odd.len(), 1, "{found:?}");
    let Remedy::Manual(remedy) = &odd[0].remedy else {
        panic!("{odd:?}")
    };
    for text in [&odd[0].subject.to_string(), &odd[0].what, remedy] {
        assert!(!text.contains('\x1b'), "{text:?}");
    }
    assert!(!remedy.contains("sandbox create"), "{remedy}");
    // One sandbox's check leaves other folders out.
    assert!(
        engine
            .state_check(Some(&name))
            .unwrap()
            .iter()
            .all(|f| f.subject == Subject::Sandbox(name.clone()))
    );
    assert!(repairs(&repair(&engine, None)).is_empty());
    assert_eq!(last_summary(&engine), "repaired 0, left 3 for a person");
    assert_eq!(engine.state_check(None).unwrap(), found);
}

#[test]
fn a_sandbox_whose_folder_is_gone_is_named_and_its_removal_clears_it() {
    let (_dir, engine, name) = with_sandbox();
    std::fs::remove_dir_all(engine.layout.sandbox_dir(name.as_str())).unwrap();
    let found = engine.state_check(None).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].what.contains("its folder"), "{found:?}");
    assert!(found[0].remedy.is_left());
    done(
        engine
            .remove_sandbox(&alice(), &name, true, Confirm::Yes)
            .unwrap(),
    );
    assert_eq!(engine.state_check(None).unwrap(), []);
}

#[test]
fn one_sandbox_is_checked_and_repaired_alone() {
    let (_dir, engine, name) = with_sandbox();
    let lab: SandboxName = "lab".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: lab.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    for n in [&name, &lab] {
        std::fs::remove_file(engine.layout.policy_file(n.as_str())).unwrap();
    }
    let found = engine.state_check(Some(&name)).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].subject, Subject::Sandbox(name.clone()));
    repair(&engine, Some(&name));
    assert!(engine.layout.policy_file(name.as_str()).exists());
    assert!(!engine.layout.policy_file(lab.as_str()).exists());

    let missing: SandboxName = "nosuch".parse().unwrap();
    let err = engine.state_check(Some(&missing)).unwrap_err();
    assert!(matches!(err, Error::NoSuchSandbox { .. }), "{err}");
}

/// A repair that cannot be made is named with why, and the sandbox's
/// records are left as they were.
#[test]
fn a_repair_that_fails_changes_no_record() {
    let (_dir, engine, name) = with_sandbox();
    let gone = put(&engine, &session_of(&engine, &name, gone_process()));
    let dir = engine.layout.sandbox_dir(name.as_str());
    std::fs::remove_file(engine.layout.policy_file(name.as_str())).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let repaired = repair(&engine, None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let failed: Vec<_> = repaired
        .iter()
        .filter(|f| matches!(f.remedy, Remedy::Failed { .. }))
        .collect();
    assert_eq!(failed.len(), 2, "{repaired:?}");
    assert!(failed.iter().all(|f| f.remedy.is_left()));
    let open = engine.state.sessions(&name, true).unwrap();
    assert_eq!(open.iter().map(|s| s.id).collect::<Vec<_>>(), [gone]);
    assert_eq!(
        last_summary(&engine),
        "repaired 0, failed to repair 2, left 0 for a person"
    );
}

#[test]
fn a_running_sandbox_whose_services_are_installed_is_left_running() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    fake.seed(engine.label(&name, Unit::Proxy).unwrap().as_str());
    set_state(&engine, &name, SandboxState::Running);
    assert_eq!(engine.state_check(None).unwrap(), []);
    repair(&engine, None);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}

#[test]
fn services_installed_while_not_recorded_running_are_named() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    fake.seed(engine.label(&name, Unit::Proxy).unwrap().as_str());
    for (state, word) in [
        (SandboxState::Stopped, "stopped"),
        (SandboxState::Created, "created"),
        (SandboxState::Failed { reason: "x".into() }, "failed"),
    ] {
        set_state(&engine, &name, state.clone());
        let found = engine.state_check(None).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .what
                .contains(&format!("installed while it is recorded {word}")),
            "{found:?}"
        );
        assert!(found[0].remedy.is_left());
        repair(&engine, None);
        assert_eq!(state_of(&engine, &name), state);
    }
}

#[test]
fn a_service_removed_by_hand_while_the_others_are_installed_is_named() {
    let (_dir, engine, fake, name) = hermes_with_services();
    fake.seed(engine.label(&name, Unit::Proxy).unwrap().as_str());
    set_state(&engine, &name, SandboxState::Running);
    let found = engine.state_check(None).unwrap();
    let partial = about(&found, "is not installed while its others are");
    assert_eq!(partial.len(), 1, "{found:?}");
    assert!(partial[0].what.contains("gateway"), "{partial:?}");
    assert!(partial[0].remedy.is_left());
}

#[test]
fn a_service_enclos_no_longer_runs_is_named_alone() {
    let (_dir, engine, fake, name) = sandbox_with_services(None);
    let proxy = engine.label(&name, Unit::Proxy).unwrap();
    let old = proxy.as_str().replace(".proxy", ".retired");
    fake.seed(&old);
    set_state(&engine, &name, SandboxState::Running);
    let found = engine.state_check(None).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].what.contains("enclos no longer runs it"),
        "{found:?}"
    );
}

/// A program run from the sandbox's folder that no session tracks is named
/// by the file it runs, though `ps` lists it as `./sleep`, and repair leaves
/// it running.
#[test]
fn a_process_no_session_tracks_is_named_and_never_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let mut escaped = FromHome::new(&engine.layout.sandbox_home(name.as_str()));
    let pid = escaped.pid();
    let found = engine.state_check(None).unwrap();
    let named = about(&found, &format!("process {pid} runs "));
    assert_eq!(named.len(), 1, "{found:?}");
    assert!(
        named[0].what.contains("/home/sleeper, listed as ./sleeper"),
        "{named:?}"
    );
    assert!(named[0].remedy.is_left());
    repair(&engine, None);
    assert!(escaped.runs(), "repair stopped it");
}

#[test]
fn a_program_of_the_sandbox_that_a_session_tracks_is_not_named() {
    let (_dir, engine, name) = with_sandbox();
    let member = FromHome::new(&engine.layout.sandbox_home(name.as_str()));
    put(&engine, &session_of(&engine, &name, member.process()));
    assert_eq!(engine.state_check(None).unwrap(), []);
}

/// A sandbox recorded running is not recorded stopped while a process runs
/// from its folder: something of it may still run.
#[test]
fn a_process_running_from_its_folder_keeps_a_sandbox_from_being_recorded_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let _escaped = FromHome::new(&engine.layout.sandbox_home(name.as_str()));
    set_state(&engine, &name, SandboxState::Running);
    let found = engine.state_check(None).unwrap();
    assert!(repairs(&found).is_empty(), "{found:?}");
    repair(&engine, None);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}
