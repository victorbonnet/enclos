use super::net::tests::{fake_net, socket};
use super::*;

#[test]
fn a_process_holds_the_listeners_its_descriptors_name_and_no_others() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    let tcp = [
        socket("0100007F:EFBE", "0A", 11),
        socket("0100007F:EFBF", "0A", 12),
    ]
    .concat();
    fake_net(&proc.join("7/net"), &tcp);
    descriptors::fake_process(proc, 7, &["socket:[11]", "/some/file", "socket:[99]"]);
    // Gone: no tables, so it holds none.
    assert_eq!(
        listeners_of_under(proc, &[7, 8], Tables::Own).unwrap(),
        [(7, "127.0.0.1:61374".parse().unwrap())]
    );
}

/// A process there with tables, whose descriptors cannot be read, is
/// not one that holds nothing.
#[test]
fn a_process_that_cannot_be_read_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    fake_net(&proc.join("7/net"), "");
    descriptors::fake_process(proc, 7, &[]);
    let fd = proc.join("7/fd");
    std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o000)).unwrap();
    let read = listeners_of_under(proc, &[7], Tables::Own);
    std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = read.unwrap_err();
    assert!(err.to_string().contains("pid 7 cannot be read"), "{err}");
}

/// A process asked for whose whole folder is refused, as `hidepid=1`
/// refuses another user's, is no more one that holds nothing.
#[test]
fn a_process_asked_for_whose_folder_is_refused_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    fake_net(&proc.join("7/net"), &socket("0100007F:EFBE", "0A", 11));
    descriptors::fake_process(proc, 7, &["socket:[11]"]);
    let folder = descriptors::refuse(&proc.join("7"));
    let read = listeners_of_under(proc, &[7], Tables::Own);
    folder.restore();
    assert!(read.is_err(), "{read:?}");
}

#[test]
fn every_holder_of_the_port_is_named_and_a_port_not_listened_on_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    let tcp = [
        socket("0100007F:EFBE", "0A", 11),
        // The same port on every address is not 127.0.0.1's.
        socket("00000000:EFBE", "0A", 12),
    ]
    .concat();
    fake_net(&proc.join("self/net"), &tcp);
    descriptors::fake_process(proc, std::process::id(), &[]);
    descriptors::fake_process(proc, 7, &["socket:[11]"]);
    descriptors::fake_process(proc, 8, &["socket:[11]"]);
    descriptors::fake_process(proc, 9, &["socket:[12]"]);
    let at: SocketAddr = "127.0.0.1:61374".parse().unwrap();
    assert_eq!(
        listeners_at_under(proc, 61374, Tables::Own).unwrap(),
        [(7, at), (8, at)]
    );
    assert!(
        listeners_at_under(proc, 61375, Tables::Own)
            .unwrap()
            .is_empty()
    );
}

/// A socket at the port that no process shown holds is one of a process
/// that cannot be read: not a port with one holder.
#[test]
fn a_listener_of_a_process_that_cannot_be_read_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    let tcp = [
        socket("0100007F:EFBE", "0A", 11),
        socket("0100007F:EFBE", "0A", 13),
    ]
    .concat();
    fake_net(&proc.join("self/net"), &tcp);
    descriptors::fake_process(proc, std::process::id(), &[]);
    descriptors::fake_process(proc, 7, &["socket:[11]"]);
    let err = listeners_at_under(proc, 61374, Tables::Own).unwrap_err();
    assert!(
        err.to_string()
            .contains("a listener at 127.0.0.1:61374 belongs to a process that cannot be read"),
        "{err}"
    );
}

/// One that closed during the look, which is why it was not found, is
/// no process that cannot be read.
#[test]
fn a_listener_closed_during_the_look_is_no_error() {
    let at = SocketAddr::from((Ipv4Addr::LOCALHOST, 61374));
    let looks = std::cell::Cell::new(0);
    let listening = || {
        looks.set(looks.get() + 1);
        Ok(match looks.get() {
            1 => BTreeSet::from([11, 13]),
            _ => BTreeSet::from([11, 14]),
        })
    };
    let held = holders_among(at, listening, || Ok(vec![(7, BTreeSet::from([11]))]));
    assert_eq!(held.unwrap(), [(7, at)]);
}

/// A process whose main thread exited has no tables and no descriptors
/// of its own: they are read through a thread that runs.
#[test]
fn a_process_is_seen_listening_through_a_thread() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    let task = proc.join("7/task");
    descriptors::fake_process(proc, 7, &[]);
    descriptors::fake_process(&task, 7, &[]);
    descriptors::fake_process(&task, 8, &["socket:[11]"]);
    fake_net(&task.join("8/net"), &socket("0100007F:EFBE", "0A", 11));
    let fd = descriptors::refuse(&proc.join("7/fd"));
    let read = listeners_of_under(proc, &[7], Tables::Own);
    fd.restore();
    assert_eq!(read.unwrap(), [(7, "127.0.0.1:61374".parse().unwrap())]);
}

/// The folder's markers held under a `/proc` of the test's own: each
/// process's descriptors, whatever they name, sorted out by marker. The
/// folder is asked for through a link, as a home may be, and `/proc`
/// writes real paths.
#[test]
fn proc_gives_each_sessions_holders() {
    let dir = tempfile::tempdir().unwrap();
    let members = dir.path().canonicalize().unwrap().join("members");
    std::fs::create_dir(&members).unwrap();
    for file in ["root-7-a", "root-9-b", "root-8-unheld", "starting-1-2"] {
        std::fs::write(members.join(file), "").unwrap();
    }
    let path = |file: &str| members.join(file).to_str().unwrap().to_owned();
    let proc = dir.path().join("proc");
    descriptors::fake_process(&proc, std::process::id(), &[]);
    descriptors::fake_process(&proc, 100, &[&path("root-7-a"), "socket:[5]"]);
    descriptors::fake_process(&proc, 200, &[&path("root-7-a"), &path("root-9-b")]);
    descriptors::fake_process(
        &proc,
        300,
        &[
            &path("starting-1-2"),
            &path("root-3-removed (deleted)"),
            &path("root-3-removed"),
            members.to_str().unwrap(),
            "/elsewhere/root-7-a",
        ],
    );
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&members, &link).unwrap();
    let held = marker_holders_under(&proc, &link, std::fs::read_dir(&link).unwrap()).unwrap();
    assert_eq!(held["root-7-a"], BTreeSet::from([100, 200]));
    assert_eq!(held["root-9-b"], BTreeSet::from([200]));
    assert_eq!(held.len(), 2, "{held:?}");
}

/// `O_PATH` takes no permission on the file, so a process of the user
/// passing through the folder must not read as a member; a descriptor
/// closed since the folder was read holds nothing.
#[test]
fn a_descriptor_that_only_names_a_marker_does_not_hold_it() {
    let dir = tempfile::tempdir().unwrap();
    let members = dir.path().canonicalize().unwrap().join("members");
    std::fs::create_dir(&members).unwrap();
    std::fs::write(members.join("root-7-a"), "").unwrap();
    let path = members.join("root-7-a");
    let path = path.to_str().unwrap();
    let proc = dir.path().join("proc");
    descriptors::fake_process(&proc, std::process::id(), &[]);
    descriptors::fake_process(&proc, 100, &[path]);
    descriptors::fake_process(&proc, 200, &[path]);
    descriptors::fake_process(&proc, 300, &[path]);
    descriptors::fake_flags(&proc.join("200/fdinfo/0"), "012000000");
    std::fs::remove_file(proc.join("300/fdinfo/0")).unwrap();
    let held = marker_holders_under(&proc, &members, std::fs::read_dir(&members).unwrap()).unwrap();
    assert_eq!(held["root-7-a"], BTreeSet::from([100]));
}

/// Another user's process, listed with its whole folder refused as on a
/// `/proc` mounted with `hidepid=1`, holds no marker that can be seen and
/// does not keep the others' from being read.
#[test]
fn a_process_whose_folder_is_refused_does_not_stop_the_look_at_markers() {
    let dir = tempfile::tempdir().unwrap();
    let members = dir.path().canonicalize().unwrap().join("members");
    std::fs::create_dir(&members).unwrap();
    std::fs::write(members.join("root-7-a"), "").unwrap();
    let path = members.join("root-7-a");
    let proc = dir.path().join("proc");
    descriptors::fake_process(&proc, std::process::id(), &[]);
    descriptors::fake_process(&proc, 100, &[path.to_str().unwrap()]);
    descriptors::fake_process(&proc, 200, &[]);
    let foreign = descriptors::refuse(&proc.join("200"));
    let entries = std::fs::read_dir(&members).unwrap();
    let held = marker_holders_under(&proc, &members, entries);
    foreign.restore();
    assert_eq!(held.unwrap()["root-7-a"], BTreeSet::from([100]));
}

#[test]
fn a_proc_that_cannot_be_read_is_an_error() {
    let members = tempfile::tempdir().unwrap();
    std::fs::write(members.path().join("root-7-a"), "").unwrap();
    let entries = std::fs::read_dir(members.path()).unwrap();
    let err = marker_holders_under(Path::new("/nonexistent"), members.path(), entries).unwrap_err();
    assert!(matches!(err, MarkerError::Proc(_)), "{err}");
}

/// Under a network namespace of the sandbox's own (ADR 0039), a program's
/// sockets are looked up in that namespace's tables, read through its
/// namespace holder, not in the program's own folder or this process's.
#[test]
fn in_a_namespace_a_programs_listeners_are_read_in_its_holders_tables() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    // The namespace holder, 50: the sandbox's tables, with the relay at the
    // proxy port and the service at 61374.
    let tables = [
        socket("0100007F:A028", "0A", 10),
        socket("0100007F:EFBE", "0A", 11),
    ]
    .concat();
    fake_net(&proc.join("50/net"), &tables);
    descriptors::fake_process(proc, 50, &["socket:[10]"]);
    // The program, 7, whose own folder shows other tables, which hold none
    // of its sockets.
    fake_net(&proc.join("7/net"), &socket("0100007F:1F90", "0A", 99));
    descriptors::fake_process(proc, 7, &["socket:[11]", "/some/file"]);
    descriptors::fake_process(proc, std::process::id(), &[]);
    let at: SocketAddr = "127.0.0.1:61374".parse().unwrap();
    assert_eq!(
        listeners_of_under(proc, &[7], Tables::Of(50)).unwrap(),
        [(7, at)]
    );
    assert!(
        listeners_of_under(proc, &[7], Tables::Own)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        listeners_at_under(proc, 61374, Tables::Of(50)).unwrap(),
        [(7, at)]
    );
    // The relay's port is the namespace holder's own.
    assert_eq!(
        listeners_at_under(proc, 41000, Tables::Of(50)).unwrap(),
        [(50, "127.0.0.1:41000".parse().unwrap())]
    );
    // A namespace holder that is gone leaves no tables to read.
    let err = listeners_of_under(proc, &[7], Tables::Of(51)).unwrap_err();
    assert!(err.to_string().contains("pid 51"), "{err}");
}

/// A process of a test's own `/proc`, with its parent and its pid in each
/// PID namespace from the outermost.
fn fake_status(proc: &Path, pid: u32, parent: u32, pids: &[u32]) {
    let folder = proc.join(pid.to_string());
    std::fs::create_dir_all(&folder).unwrap();
    let nspid: Vec<String> = pids.iter().map(u32::to_string).collect();
    std::fs::write(
        folder.join("status"),
        format!(
            "Name:\tx\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nNSpid:\t{}\n",
            nspid.join("\t")
        ),
    )
    .unwrap();
}

/// bubblewrap's outer process 100 runs `enclos inside`, 101, as PID 1 of a
/// namespace of its own; the command it started is PID 2 there, and what
/// the command started, or an orphan `enclos inside` reaps, is not it.
#[test]
fn the_program_is_the_second_process_of_the_sessions_pid_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    fake_status(proc, 1, 0, &[1]);
    fake_status(proc, 100, 1, &[100]);
    fake_status(proc, 101, 100, &[101, 1]);
    assert_eq!(program_under(proc, 100).unwrap(), None);
    fake_status(proc, 103, 101, &[103, 3]);
    fake_status(proc, 102, 101, &[102, 2]);
    fake_status(proc, 104, 102, &[104, 4]);
    // Another session's, under another root.
    fake_status(proc, 200, 1, &[200]);
    fake_status(proc, 201, 200, &[201, 1]);
    fake_status(proc, 202, 201, &[202, 2]);
    assert_eq!(program_under(proc, 100).unwrap(), Some(102));
    assert_eq!(program_under(proc, 200).unwrap(), Some(202));
    // A root with no PID namespace below it, as a Seatbelt session's.
    assert_eq!(program_under(proc, 104).unwrap(), None);
    assert_eq!(program_under(proc, 999).unwrap(), None);
}

/// `enclos holder join` 300 waits for bubblewrap's outer process 301, whose
/// `enclos inside` 302 is PID 1 of the session's namespace: the program is
/// still the second process there. One more step on the host is not looked
/// through.
#[test]
fn the_program_is_found_below_the_join_that_waits_for_bubblewrap() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    fake_status(proc, 1, 0, &[1]);
    fake_status(proc, 300, 1, &[300]);
    fake_status(proc, 301, 300, &[301]);
    fake_status(proc, 302, 301, &[302, 1]);
    assert_eq!(program_under(proc, 300).unwrap(), None);
    fake_status(proc, 303, 302, &[303, 2]);
    assert_eq!(program_under(proc, 300).unwrap(), Some(303));
    fake_status(proc, 400, 1, &[400]);
    fake_status(proc, 401, 400, &[401]);
    fake_status(proc, 402, 401, &[402]);
    fake_status(proc, 403, 402, &[403, 1]);
    fake_status(proc, 404, 403, &[404, 2]);
    assert_eq!(program_under(proc, 400).unwrap(), None);
}

/// On a `/proc` mounted with `hidepid=1`, another user's process is
/// listed and its `status` refused: it is no process of the session's, so
/// the look goes on without it. The root refused is a look that could not
/// happen, not a session with no program yet.
#[test]
fn a_process_whose_status_is_refused_is_left_out_unless_it_is_the_root() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    fake_status(proc, 7, 1, &[7]);
    fake_status(proc, 100, 1, &[100]);
    fake_status(proc, 101, 100, &[101, 1]);
    fake_status(proc, 102, 101, &[102, 2]);
    let foreign = descriptors::refuse(&proc.join("7"));
    let program = program_under(proc, 100);
    let refused_root = program_under(proc, 7);
    foreign.restore();
    assert_eq!(program.unwrap(), Some(102));
    let err = refused_root.unwrap_err();
    assert!(err.to_string().contains("7/status"), "{err}");
}

#[test]
fn a_status_gives_the_parent_and_each_namespaces_pid() {
    assert_eq!(
        parse_status("Name:\tbash\nPPid:\t7\nNSpid:\t12\t2\n"),
        Some((7, vec![12, 2]))
    );
    assert_eq!(parse_status("PPid:\t7\n"), None);
    assert_eq!(parse_status("PPid:\tx\nNSpid:\t1\n"), None);
}

#[test]
fn two_processes_share_a_network_when_their_namespace_links_match() {
    let dir = tempfile::tempdir().unwrap();
    let proc = dir.path();
    for (pid, net) in [
        (7, "net:[4026532001]"),
        (8, "net:[4026532001]"),
        (9, "net:[4026531840]"),
    ] {
        let ns = proc.join(pid.to_string()).join("ns");
        std::fs::create_dir_all(&ns).unwrap();
        std::os::unix::fs::symlink(net, ns.join("net")).unwrap();
    }
    assert!(same_network_under(proc, 7, 8).unwrap());
    assert!(!same_network_under(proc, 7, 9).unwrap());
    assert!(same_network_under(proc, 7, 10).is_err());
}

/// A connection this process makes to itself is this user's, read from the
/// host's own tables, and a closed one is no one's.
#[cfg(target_os = "linux")]
#[test]
fn a_loopback_connections_client_is_this_users() {
    use std::net::{Ipv4Addr, TcpStream};
    let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    let server = accepted.local_addr().unwrap();
    let me = rustix::process::getuid().as_raw();
    assert_eq!(tcp_client_owner(peer, server).unwrap(), Some(me));
    drop(client);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(tcp_client_owner(peer, server).unwrap(), None);
}

/// On a real `/proc` mounted with `hidepid=1`, where root's pid 1 is listed
/// and refused, every scan reads and leaves it out, while a look at it alone
/// is an error. CI's `confinement` job mounts such a `/proc` in a mount
/// namespace of its own, leaving the runner's as it is, and runs this as the
/// runner's user with `ENCLOS_HIDEPID_TESTS` set; elsewhere it does nothing.
#[cfg(target_os = "linux")]
#[test]
fn on_a_runner_every_scan_leaves_out_what_hidepid_refuses() {
    if std::env::var_os("ENCLOS_HIDEPID_TESTS").is_none() {
        eprintln!("hidepid test not run: CI's confinement job runs it");
        return;
    }
    let proc = Path::new(PROC);
    let me = std::process::id();
    let root = rustix::process::getuid().is_root();
    assert!(!root, "root reads every process: run as the runner's user");
    // The control: pid 1 is listed, and nothing in its folder reads.
    assert!(proc.join("1").is_dir());
    let refused = std::fs::read(proc.join("1/status")).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
    assert!(std::fs::read_dir(proc.join("1/task")).is_err());

    assert_eq!(descriptors::of(proc, 1).unwrap(), Descriptors::Unreadable);
    let held = descriptors::every_process(proc).unwrap();
    assert!(held.iter().any(|(pid, _)| *pid == me), "{held:?}");
    assert!(!held.iter().any(|(pid, _)| *pid == 1), "{held:?}");
    let every = lineages(proc).unwrap();
    assert!(every.contains_key(&me) && !every.contains_key(&1));
    assert_eq!(program_under(proc, me).unwrap(), None);
    assert!(program_under(proc, 1).is_err());
    assert!(processes().unwrap().iter().any(|p| p.pid == me));
    assert!(program_files().unwrap().contains_key(&me));
}
