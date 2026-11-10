use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::sockets::{Address, Socket};
use super::host::{HostFacts, OtherProcess, OtherSocket};
use super::routes::CRONTAB;
#[cfg(target_os = "linux")]
use super::routes::environment_probe;
use super::*;
#[cfg(target_os = "linux")]
use crate::probes::TARGET_VARIABLE;
use crate::probes::{Proof, probes};

fn inputs(dir: &Path) -> ProbeInputs {
    let home = dir.join("enclos/sandboxes/lab/home");
    std::fs::create_dir_all(home.join("proj/config")).unwrap();
    ProbeInputs {
        user_home: dir.to_owned(),
        data: dir.join("enclos"),
        config_file: dir.join("enclos/config.toml"),
        hidden_files: Vec::new(),
        sandbox_dir: dir.join("enclos/sandboxes/lab"),
        other_sandboxes: vec![dir.join("enclos/sandboxes/other")],
        writes: vec![home.clone()],
        read_deny: Vec::new(),
        home: home.clone(),
        workspaces: vec![dir.join("work")],
        unmovable: vec![home.clone(), home.join("proj/config")],
        host_sockets: Vec::new(),
        proxy_port: 41001,
        listen: false,
        target: Some(4242),
        other_terminal: None,
        tag: 7,
        limits: Default::default(),
    }
}

/// What a host with everything the probes aim at would give.
fn everything() -> HostFacts {
    HostFacts {
        runtime_dir: Some(PathBuf::from("/run/user/1000")),
        session_bus: Some("unix:path=/run/user/1000/bus".to_owned()),
        system_bus: Some(PathBuf::from(host::SYSTEM_BUS)),
        sockets: vec![
            Socket {
                address: Address::Path(PathBuf::from("/run/docker.sock")),
                kind: 1,
            },
            Socket {
                address: Address::Abstract("/tmp/.X11-unix/X0".to_owned()),
                kind: 1,
            },
        ],
        abstract_target: Some("enclos-probe-7".to_owned()),
        loopback_target: Some(40000),
        other_processes: vec![OtherProcess {
            sandbox: "other".to_owned(),
            pid: 77,
        }],
        other_sockets: vec![OtherSocket {
            sandbox: "other".to_owned(),
            socket: Socket {
                address: Address::Abstract("held".to_owned()),
                kind: 1,
            },
            table: PathBuf::from("/proc/88/net/unix"),
        }],
        manager_procs: Ok(PathBuf::from("/sys/fs/cgroup/user.slice/cgroup.procs")),
    }
}

fn own(facts: HostFacts, given: Vec<PathBuf>) -> BubblewrapProbes {
    BubblewrapProbes { facts, given }
}

fn named<'a>(list: &'a [Probe], name: &str) -> &'a Probe {
    list.iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("no probe `{name}` in {:?}", names(list)))
}

fn names(list: &[Probe]) -> Vec<&str> {
    list.iter().map(|p| p.name.as_str()).collect()
}

/// Each route of milestone 3's step 5 has a probe, with a control on the
/// host, and none waits for `--host-services`.
#[test]
fn every_linux_route_has_a_probe_with_a_control() {
    let dir = tempfile::tempdir().unwrap();
    let i = inputs(dir.path());
    let own = own(everything(), Vec::new());
    let list = probes(&i, &own);
    let routes: Vec<&str> = list.iter().map(|p| p.route).collect();
    // Those of programs the host may lack (`setuid`, `crontab`, `at`) are
    // in `programs_that_would_gain_privileges_are_closed_by_bubblewrap_itself`.
    for route in [
        "session bus",
        "system bus",
        "systemd --user",
        "host sockets",
        "abstract sockets",
        "network",
        "vsock",
        "dns",
        "signals",
        "ptrace",
        "environment",
        "terminals",
        "user namespace",
        "mounts",
        "cgroup",
        "renames",
        "writable folders",
    ] {
        assert!(routes.contains(&route), "no {route} probe in {routes:?}");
    }
    for probe in &list {
        assert!(
            !matches!(probe.proof, Proof::ProxyRefuses) || probe.route == "network",
            "{} has no control",
            probe.name
        );
    }
    assert!(own.host_services(&i).is_empty());
    named(&list, "connect to @held, of sandbox other");
    named(
        &list,
        "read the start-up environment of a process of sandbox other",
    );
    named(
        &list,
        "connect to @enclos-probe-7, where enclos listens on the host",
    );
}

/// The home and each workspace are writable folders, renamed beside
/// themselves; a folder inside one that holds a mask is a rename of its own.
#[test]
fn the_home_is_a_writable_folder_and_a_folder_holding_a_mask_a_rename() {
    let dir = tempfile::tempdir().unwrap();
    let i = inputs(dir.path());
    let list = probes(&i, &own(everything(), Vec::new()));
    let home = named(&list, &format!("rename {}", i.home.display()));
    assert_eq!(home.route, "writable folders");
    let inner = named(
        &list,
        &format!("rename {}", i.home.join("proj/config").display()),
    );
    assert_eq!(inner.route, "renames");
    assert_eq!(
        named(&list, "remove the sandbox home").route,
        "writable folders"
    );
}

/// What the host lacks is said, never left out silently.
#[test]
fn what_the_host_lacks_is_said() {
    let dir = tempfile::tempdir().unwrap();
    let i = inputs(dir.path());
    let bare = own(HostFacts::default(), Vec::new());
    let said = bare.not_here(&i).join("; ");
    for what in [
        "the session bus",
        "the system bus",
        "the `systemd --user` manager",
        "a listener of enclos's own",
        "another sandbox's start-up environment",
        "the session's cgroup (not looked for)",
    ] {
        assert!(said.contains(what), "{what}: {said}");
    }
    let list = probes(&i, &bare);
    assert!(
        !list
            .iter()
            .any(|p| p.route == "cgroup" || p.route == "session bus")
    );
}

/// The script of a read probe, run as the host would run its control.
fn reads(probe: &Probe) -> bool {
    Command::new("/bin/sh")
        .args(["-c", &probe.script])
        .status()
        .unwrap()
        .success()
}

/// A mask reads empty, so a read is closed when it reads nothing; an entry
/// on the way to what the sandbox is given does not count.
#[test]
fn a_read_counts_what_it_reads_but_the_way_to_what_the_sandbox_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let given = run.join("lab/visible");
    std::fs::create_dir_all(&given).unwrap();
    let own = own(HostFacts::default(), vec![given.clone()]);
    let probe = own.read("enclos files", &run);
    assert_eq!(probe.name, format!("read {}", run.display()));
    assert!(!reads(&probe), "only the way to its own: {}", probe.script);
    std::fs::create_dir_all(run.join("other")).unwrap();
    assert!(reads(&probe), "another sandbox's: {}", probe.script);

    let file = dir.path().join("token");
    std::fs::write(&file, "").unwrap();
    let probe = own.read("sensitive files", &file);
    assert!(!reads(&probe), "an empty file reads nothing");
    std::fs::write(&file, "x").unwrap();
    assert!(reads(&probe));
    let missing = own.read("sensitive files", &dir.path().join("missing"));
    assert!(!reads(&missing));
    assert!(
        matches!(probe.proof, Proof::Control { expect: Expect::Own(r), .. } if r == READS_NOTHING)
    );
}

#[test]
fn a_read_that_reads_something_is_open_and_one_that_reads_nothing_closed() {
    assert_eq!((READS_NOTHING.read)(false, ""), Outcome::Closed);
    assert!(matches!((READS_NOTHING.read)(true, ""), Outcome::Open(_)));
}

#[test]
fn crontab_reaching_the_spool_is_open() {
    assert_eq!(
        (CRONTAB.read)(false, "/var/spool/cron/crontabs/u: Permission denied"),
        Outcome::Closed
    );
    assert!(matches!(
        (CRONTAB.read)(false, "no crontab for u"),
        Outcome::Open(_)
    ));
    assert!(matches!((CRONTAB.read)(true, ""), Outcome::Open(_)));
}

/// A setuid program and crontab show no enclos rule: bubblewrap itself
/// closes them.
#[test]
fn programs_that_would_gain_privileges_are_closed_by_bubblewrap_itself() {
    let dir = tempfile::tempdir().unwrap();
    let i = inputs(dir.path());
    let list = probes(&i, &own(everything(), Vec::new()));
    for probe in list
        .iter()
        .filter(|p| ["setuid", "crontab", "at"].contains(&p.route))
    {
        assert_eq!(probe.closed_by, Some(ITSELF), "{}", probe.name);
    }
}

/// A process's start-up environment is read from `/proc`: the probe's
/// script finds a line the host gave the process, and not one it did not.
#[cfg(target_os = "linux")]
#[test]
fn the_environment_probe_finds_the_line_the_host_gave_a_process() {
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .env(TARGET_VARIABLE, "1")
        .spawn()
        .unwrap();
    let found = environment_probe("e", child.id(), &format!("{TARGET_VARIABLE}=1"));
    let other = environment_probe("e", child.id(), "ENCLOS_SANDBOX=other");
    let (found, other) = (reads(&found), reads(&other));
    let _ = child.kill();
    let _ = child.wait();
    assert!(found);
    assert!(!other);
}
