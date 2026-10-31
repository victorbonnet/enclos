//! A session's cgroup (design §8). The first test reads a stand-in for the
//! cgroup hierarchy and runs anywhere. Those named `on_a_runner` start real
//! scopes in the user's systemd manager, so only CI's `cgroups` job runs
//! them.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::*;
use crate::lifecycle::cgroup::Hierarchy;
use crate::lifecycle::process::{Signal, is_same, reference, signal_process};
use crate::model::sandbox::SandboxState;
use crate::model::session::{ProcessRef, SessionKind, SessionRecord};

#[test]
fn what_a_sessions_cgroup_holds_is_listed_whatever_its_group_and_parent() {
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let mut lab = Lab::new();
    let root_ended = Command::new("/bin/sh").args(["-c", ":"]).spawn();
    let mut root_ended = root_ended.unwrap();
    let root = crate::lifecycle::process::reference_of_child(&root_ended).unwrap();
    root_ended.wait().unwrap();
    // Started apart: only the cgroup ties it to the session.
    let mut member = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let hierarchy = tempfile::tempdir().unwrap();
    let scope = hierarchy.path().join("s.scope");
    std::fs::create_dir(&scope).unwrap();
    std::fs::write(scope.join("cgroup.procs"), format!("{}\n", member.id())).unwrap();
    lab.engine.cgroups = Hierarchy::at(hierarchy.path());
    let session = SessionRecord {
        id: crate::model::session::SessionId(0),
        sandbox: lab.name.clone(),
        kind: SessionKind::Exec,
        service: None,
        version: 1,
        snapshot: lab.engine.active_policy(&lab.name).unwrap().1.id,
        compiled: None,
        root,
        pgid: None,
        cgroup: Some("/s.scope".into()),
        tracked: Vec::new(),
        started_at: crate::model::now(),
        ended_at: None,
    };
    lab.engine
        .write(
            &alice(),
            "test",
            None,
            |_| String::new(),
            |lock| Ok(lab.engine.state.put_session(lock, &session).map(|_| ())?),
        )
        .unwrap();

    let view = lab.engine.show_sandbox(&lab.name).unwrap();
    let pids: Vec<u32> = view.sessions[0].members.iter().map(|m| m.pid).collect();
    assert_eq!(pids, [member.id()]);

    // Once the cgroup is gone, so is the session.
    std::fs::remove_dir_all(&scope).unwrap();
    let view = lab.engine.show_sandbox(&lab.name).unwrap();
    assert!(view.sessions[0].gone(), "{:?}", view.sessions[0]);
    member.kill().unwrap();
    member.wait().unwrap();
}

/// Whether to run the tests below, which start scopes in the user's systemd
/// manager, so only in CI's `cgroups` job: it sets `ENCLOS_CGROUP_TESTS`, and
/// they refuse anywhere else.
fn on_a_runner() -> bool {
    if std::env::var("ENCLOS_CGROUP_TESTS").as_deref() != Ok("1") {
        eprintln!("cgroup tests not run: CI's cgroups job runs them");
        return false;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    assert!(
        var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
        "these tests start scopes in the user's manager: they run only on a GitHub-hosted runner"
    );
    true
}

fn lab_with_scopes() -> Lab {
    let mut lab = Lab::new();
    lab.engine.scopes = true;
    lab
}

/// A program that detaches a process and exits once that process wrote its
/// pid to `~/detached`: a double fork with `setsid`, then `more` Python
/// statements, then a long sleep.
fn detaching(more: &str) -> Vec<std::ffi::OsString> {
    let script = format!(
        "import os, signal, time
path = os.environ['HOME'] + '/detached'
if os.fork():
    while not os.path.exists(path):
        time.sleep(0.02)
    os._exit(0)
os.setsid()
if os.fork():
    os._exit(0)
partial = path + '.partial'
with open(partial, 'w') as f:
    f.write(str(os.getpid()))
os.rename(partial, path)
{more}
time.sleep(600)
"
    );
    vec!["/usr/bin/python3".into(), "-c".into(), script.into()]
}

fn read_when_there(file: &Path) -> String {
    let start = Instant::now();
    while !file.exists() {
        assert!(start.elapsed() < Duration::from_secs(30), "{file:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::read_to_string(file).unwrap()
}

/// `process` must not outlive a test that failed.
struct Ended(ProcessRef);

impl Drop for Ended {
    fn drop(&mut self) {
        // The test's own process, checked by pid and start time.
        let _ = signal_process(&self.0, Signal::Kill);
    }
}

fn open_exec_session(lab: &Lab) -> SessionRecord {
    lab.engine
        .state
        .sessions(&lab.name, true)
        .unwrap()
        .into_iter()
        .find(|s| s.kind == SessionKind::Exec)
        .unwrap()
}

/// Runs `program`, whose detached process is listed as a member of its
/// session's cgroup, and is ended by `sandbox stop`, which leaves the sandbox
/// stopped and the cgroup removed.
fn listed_and_stopped(lab: &Lab, program: Vec<std::ffi::OsString>) -> Vec<String> {
    done(
        lab.engine
            .exec(&alice(), &lab.name, program, Confirm::Yes)
            .unwrap(),
    );
    let pid: u32 = read_when_there(&lab.home.join("detached"))
        .trim()
        .parse()
        .unwrap();
    let detached = reference(pid).unwrap().expect("the detached process runs");
    let _ended = Ended(detached.clone());
    let descriptors: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    let session = open_exec_session(lab);
    let cgroup = session.cgroup.clone().expect("the session has a cgroup");
    let held = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    assert_eq!(held.trim(), format!("0::{cgroup}"));
    let view = lab.engine.show_sandbox(&lab.name).unwrap();
    assert!(
        view.sessions
            .iter()
            .any(|v| v.session.id == session.id && v.members.iter().any(|m| m.pid == pid)),
        "{:?}",
        view.sessions
    );

    let report = done(
        lab.engine
            .stop_sandbox(&alice(), &lab.name, Confirm::Yes)
            .unwrap(),
    );
    assert!(report.survivors.is_empty(), "{:?}", report.survivors);
    assert!(!is_same(&detached).unwrap(), "it survived the stop");
    let record = lab.engine.state.get(&lab.name).unwrap().unwrap();
    assert_eq!(record.state, SandboxState::Stopped);

    let folder = format!("/sys/fs/cgroup{cgroup}");
    let start = Instant::now();
    while Path::new(&folder).exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "{folder}");
        std::thread::sleep(Duration::from_millis(20));
    }
    descriptors
}

#[test]
fn on_a_runner_a_double_fork_with_setsid_is_a_member_and_is_stopped() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    listed_and_stopped(&lab, detaching("pass"));
}

#[test]
fn on_a_runner_one_that_also_closes_every_descriptor_is_a_member_and_is_stopped() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    let descriptors = listed_and_stopped(&lab, detaching("os.closerange(0, 1 << 16)"));
    assert!(descriptors.is_empty(), "{descriptors:?}");
}

#[test]
fn on_a_runner_one_that_ignores_term_is_killed_through_the_cgroup() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    listed_and_stopped(
        &lab,
        detaching("signal.signal(signal.SIGTERM, signal.SIG_IGN)"),
    );
}

#[test]
fn on_a_runner_a_program_keeps_its_exit_status_and_gets_no_way_to_the_manager() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    let script = "/usr/bin/env > \"$HOME/seen\"; exit 7";
    let end = done(
        lab.engine
            .exec(
                &alice(),
                &lab.name,
                vec!["/bin/sh".into(), "-c".into(), script.into()],
                Confirm::Yes,
            )
            .unwrap(),
    );
    assert_eq!(end.exit, 7);
    assert_eq!(end.left, crate::engine::Left::Nothing);
    let seen = std::fs::read_to_string(lab.home.join("seen")).unwrap();
    for variable in [
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "INVOCATION_ID",
    ] {
        assert!(!seen.contains(variable), "{seen}");
    }
    assert!(seen.contains("HOME="), "{seen}");
}

#[test]
fn on_a_runner_a_sandbox_with_a_hyphen_has_a_slice_of_its_own_with_no_parent() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    let name: SandboxName = "pi-bot".parse().unwrap();
    let spec = crate::engine::SandboxSpec {
        name: name.clone(),
        backend: BackendKind::Seatbelt,
        template: "assistant".parse().unwrap(),
    };
    done(
        lab.engine
            .create_sandbox(&alice(), spec, Confirm::Yes)
            .unwrap(),
    );
    let home = lab.engine.layout.sandbox_home("pi-bot");
    let script = format!("/bin/cat /proc/self/cgroup > {}/seen", home.display());
    done(
        lab.engine
            .exec(
                &alice(),
                &name,
                vec!["/bin/sh".into(), "-c".into(), script.into()],
                Confirm::Yes,
            )
            .unwrap(),
    );
    let install = lab.engine.layout.install_id().unwrap();
    let seen = std::fs::read_to_string(home.join("seen")).unwrap();
    let slice = format!("user@{}.service", rustix::process::getuid().as_raw());
    let slice = format!("/{slice}/enclos.{install}.pi\\x2dbot.slice/");
    let stopped = lab.engine.stop_sandbox(&alice(), &name, Confirm::Yes);
    assert!(done(stopped.unwrap()).survivors.is_empty());
    assert!(seen.contains(&slice), "{seen}");
}

#[test]
fn on_a_runner_a_service_runs_in_a_scope_of_its_own() {
    if !on_a_runner() {
        return;
    }
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    assert!(done(lab.install(GATEWAY, Confirm::Yes).unwrap()).installed);
    let ended = Arc::new(AtomicBool::new(false));
    let teller = end_once_started(lab.home.join("gateway-pids"), Arc::clone(&ended), || {});
    lab.engine
        .launch_until(&alice(), &lab.name, "gateway", &ended)
        .unwrap();
    teller.join().unwrap();
    let sessions = lab.engine.state.sessions(&lab.name, false).unwrap();
    let service = sessions.iter().find(|s| s.kind == SessionKind::Service);
    let cgroup = service.and_then(|s| s.cgroup.clone());
    assert!(
        cgroup.is_some_and(|c| c.ends_with(".scope")),
        "{sessions:?}"
    );
}

#[test]
fn on_a_runner_nothing_stays_in_a_slice_after_its_session() {
    if !on_a_runner() {
        return;
    }
    let _turn = HOST_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab_with_scopes();
    listed_and_stopped(&lab, detaching("pass"));
    let install = lab.engine.layout.install_id().unwrap();
    let units = Command::new("/usr/bin/systemctl")
        .args(["--user", "list-units", "--all", "--plain", "--no-legend"])
        .arg(format!("enclos.{install}.*.scope"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(units.status.success(), "{units:?}");
    let listed = String::from_utf8_lossy(&units.stdout);
    assert!(listed.trim().is_empty(), "{listed}");
}
