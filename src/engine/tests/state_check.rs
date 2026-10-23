//! `state check` and `state repair` (design §11): records compared with the
//! host, repaired where that is safe, named otherwise. No test signals a
//! process it did not start.

use std::os::unix::fs::PermissionsExt;

use super::policy::with_sandbox;
use super::sandbox::{Sleeping, gone_process, put, session_of, while_waiting};
use super::services::{hermes_with_services, sandbox_with_services};
use super::*;
use crate::engine::service::Unit;
use crate::engine::{Finding, Remedy, Subject};
use crate::lifecycle::programs::tests::Sleeper;
use crate::model::sandbox::{SandboxName, SandboxState};

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
    engine.state_repair(&alice(), only).unwrap()
}

fn last_summary(engine: &Engine) -> String {
    let audit = engine.audit(None).unwrap();
    let last = audit.last().unwrap();
    assert_eq!(last.intent.command, "state repair");
    last.finished.as_ref().unwrap().outcome.message.clone()
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
    // A check, the repair's dry run, changes nothing and records nothing.
    let entries = engine.audit(None).unwrap().len();
    assert_eq!(repairs(&found), ["record its end", "record it stopped"]);
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

/// A lost `policy.toml` whose text enclos does not keep is named, with the
/// template the active policy is built on, not the one the sandbox was
/// created from.
#[test]
fn a_lost_policy_file_without_its_text_names_the_active_template() {
    let (_dir, engine, name) = with_sandbox();
    let minimal: crate::model::policy::TemplateName = "minimal".parse().unwrap();
    let mut snapshot =
        crate::policy::resolve(&crate::policy::initial_overrides("home", &minimal), None).unwrap();
    // The text stored no longer matches the hash its inputs name.
    snapshot.overrides.push_str("# changed\n");
    let lock = engine.state.lock().unwrap();
    engine
        .state
        .save_policy(&lock, &name, &snapshot, &alice(), None)
        .unwrap();
    drop(lock);
    std::fs::remove_file(engine.layout.policy_file(name.as_str())).unwrap();
    let found = engine.state_check(Some(&name)).unwrap();
    assert_eq!(repairs(&found), Vec::<String>::new());
    let lost = about(&found, "policy.toml is gone");
    let [lost] = lost.as_slice() else {
        panic!("{found:?}");
    };
    let Remedy::Manual(how) = &lost.remedy else {
        panic!("{lost:?}");
    };
    assert!(how.contains("`extends = \"minimal\"`"), "{how}");
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

/// A repair that cannot be made is named with its own error, the audit
/// entry says it failed, and the sandbox's other repairs are still made:
/// writing `policy.toml` and recording a session's end do not depend on
/// each other.
#[test]
fn a_repair_that_fails_is_named_alone_and_the_others_are_made() {
    let (_dir, engine, name) = with_sandbox();
    put(&engine, &session_of(&engine, &name, gone_process()));
    let dir = engine.layout.sandbox_dir(name.as_str());
    std::fs::remove_file(engine.layout.policy_file(name.as_str())).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let repaired = repair(&engine, None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let failed: Vec<_> = repaired
        .iter()
        .filter_map(|f| match &f.remedy {
            Remedy::Failed { repair, error } => Some((repair.to_string(), error.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(failed.len(), 1, "{repaired:?}");
    assert!(
        failed[0].0.starts_with("write policy.toml again"),
        "{failed:?}"
    );
    assert!(failed[0].1.contains("policy.toml"), "{failed:?}");
    assert_eq!(repairs(&repaired), ["record its end"]);
    assert!(engine.state.sessions(&name, true).unwrap().is_empty());
    assert_eq!(
        last_summary(&engine),
        "repaired 1, failed to repair 1, left 1 for a person"
    );
    let audit = engine.audit(None).unwrap();
    let finished = audit.last().unwrap().finished.as_ref().unwrap();
    assert_eq!(
        finished.outcome.result,
        crate::model::audit::AuditResult::Failed
    );
}

/// A session whose root is gone but whose marker a process still holds is
/// running: repair neither ends it nor records the sandbox stopped (ADR
/// 0030), though that process runs a program from elsewhere.
#[test]
fn a_session_kept_alive_by_its_marker_is_not_ended() {
    let (_dir, engine, name) = with_sandbox();
    let marker = engine.new_marker(&name).unwrap();
    let mut command = std::process::Command::new("/bin/sleep");
    command.arg("30");
    let (child, marked) = marker.spawn(&mut command).unwrap();
    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _child = Reap(child);
    let root = gone_process();
    engine.name_marker(&name, marked, &root).unwrap();
    let id = put(&engine, &session_of(&engine, &name, root));
    set_state(&engine, &name, SandboxState::Running);
    assert_eq!(engine.state_check(None).unwrap(), []);
    repair(&engine, None);
    let open: Vec<_> = engine
        .state
        .sessions(&name, true)
        .unwrap()
        .iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(open, [id]);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}

/// A sandbox whose files enclos cannot look at is one finding, and the
/// others are still checked and repaired.
#[test]
fn a_sandbox_enclos_cannot_look_at_does_not_hide_the_others() {
    let (_dir, engine, name) = with_sandbox();
    let lab: SandboxName = "lab".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: lab.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(engine.create_sandbox(&alice(), spec, Confirm::Yes).unwrap());
    std::fs::remove_file(engine.layout.policy_file(lab.as_str())).unwrap();
    let dir = engine.layout.sandbox_dir(name.as_str());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let found = engine.state_check(None);
    let repaired = repair(&engine, None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let found = found.unwrap();
    let cannot = about(&found, "enclos cannot look at it");
    assert_eq!(cannot.len(), 1, "{found:?}");
    assert_eq!(cannot[0].subject, Subject::Sandbox(name.clone()));
    assert!(cannot[0].remedy.is_left());
    assert!(
        found
            .iter()
            .any(|f| f.subject == Subject::Sandbox(lab.clone()) && !f.remedy.is_left()),
        "{found:?}"
    );
    assert!(
        repaired
            .iter()
            .any(|f| f.subject == Subject::Sandbox(lab.clone()))
    );
    assert!(engine.layout.policy_file(lab.as_str()).exists());
}

/// A sandbox folder replaced by a file is that one finding: no marker
/// lookup in it blames `lsof`.
#[test]
fn a_sandbox_folder_that_is_a_file_is_one_finding() {
    let (_dir, engine, name) = with_sandbox();
    let dir = engine.layout.sandbox_dir(name.as_str());
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::write(&dir, "not a folder").unwrap();
    let found = engine.state_check(None).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].what.contains("is not a folder"), "{found:?}");
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
/// by the file it runs, though `ps` lists it as `./sleeper`, and repair leaves
/// it running.
#[test]
fn a_process_no_session_tracks_is_named_and_never_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let mut escaped = Sleeper::in_folder(&engine.layout.sandbox_home(name.as_str()));
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
    let member = Sleeper::in_folder(&engine.layout.sandbox_home(name.as_str()));
    put(
        &engine,
        &session_of(
            &engine,
            &name,
            crate::lifecycle::process::reference(member.pid())
                .unwrap()
                .unwrap(),
        ),
    );
    assert_eq!(engine.state_check(None).unwrap(), []);
}

/// A sandbox recorded running is not recorded stopped while a process runs
/// from its folder: something of it may still run.
#[test]
fn a_process_running_from_its_folder_keeps_a_sandbox_from_being_recorded_stopped() {
    let (_dir, engine, name) = with_sandbox();
    let _escaped = Sleeper::in_folder(&engine.layout.sandbox_home(name.as_str()));
    set_state(&engine, &name, SandboxState::Running);
    let found = engine.state_check(None).unwrap();
    assert!(repairs(&found).is_empty(), "{found:?}");
    repair(&engine, None);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}

/// With its folder gone, enclos cannot look for processes running from it,
/// so it does not record the sandbox stopped itself.
#[test]
fn a_sandbox_whose_folder_is_gone_is_not_recorded_stopped_by_repair() {
    let (_dir, engine, name) = with_sandbox();
    set_state(&engine, &name, SandboxState::Running);
    std::fs::remove_dir_all(engine.layout.sandbox_dir(name.as_str())).unwrap();
    let found = engine.state_check(None).unwrap();
    assert!(repairs(&found).is_empty(), "{found:?}");
    assert_eq!(
        about(&found, "no session or service of it runs").len(),
        1,
        "{found:?}"
    );
    repair(&engine, None);
    assert_eq!(state_of(&engine, &name), SandboxState::Running);
}
