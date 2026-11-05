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
        listeners_of_under(proc, &[7, 8]).unwrap(),
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
    let read = listeners_of_under(proc, &[7]);
    std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = read.unwrap_err();
    assert!(err.to_string().contains("pid 7 cannot be read"), "{err}");
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
    assert_eq!(listeners_at_under(proc, 61374).unwrap(), [(7, at), (8, at)]);
    assert!(listeners_at_under(proc, 61375).unwrap().is_empty());
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
    let err = listeners_at_under(proc, 61374).unwrap_err();
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
    let read = listeners_of_under(proc, &[7]);
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

#[test]
fn a_proc_that_cannot_be_read_is_an_error() {
    let members = tempfile::tempdir().unwrap();
    std::fs::write(members.path().join("root-7-a"), "").unwrap();
    let entries = std::fs::read_dir(members.path()).unwrap();
    let err = marker_holders_under(Path::new("/nonexistent"), members.path(), entries).unwrap_err();
    assert!(matches!(err, MarkerError::Proc(_)), "{err}");
}
