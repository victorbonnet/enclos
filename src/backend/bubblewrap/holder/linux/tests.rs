use super::*;

/// What `serve` sends, `ask` reads back: the ports, two descriptors
/// that are this process's namespaces and close on `exec`, and the
/// namespace holder's pid from the socket.
#[test]
fn a_namespace_holders_answer_is_its_ports_its_namespaces_and_its_pid() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/lab/holder.sock");
    stand_in(&socket, (32768, 60999));
    let answer = ask(&socket).unwrap();
    assert_eq!(answer.ephemeral, 32768..=60999);
    assert_eq!(answer.pid, std::process::id());
    let [user, net] = &answer.namespaces;
    for (fd, kind) in [(user, "user"), (net, "net")] {
        let held = std::fs::read_link(format!("/proc/self/fd/{}", rustix_fd(fd))).unwrap();
        let own = std::fs::read_link(format!("/proc/self/ns/{kind}")).unwrap();
        assert_eq!(held, own, "{kind}");
        let flags = rustix::io::fcntl_getfd(fd).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "{kind}");
    }
}

fn rustix_fd(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd;
    fd.as_raw_fd()
}

#[test]
fn no_namespace_holder_is_said_with_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("holder.sock");
    let Err(why) = ask(&socket) else {
        panic!("answered");
    };
    assert!(why.contains("no namespace holder answers on"), "{why}");
    assert!(why.contains("holder.sock"), "{why}");
}

/// An enter that cannot reach the namespace holder runs nothing.
#[test]
fn an_enter_with_no_namespace_holder_runs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ran = dir.path().join("ran");
    let command: Vec<OsString> = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!("touch '{}'", ran.display()).into(),
    ];
    let why = enter(&dir.path().join("holder.sock"), &command);
    assert!(why.contains("no namespace holder answers"), "{why}");
    assert!(!ran.exists());
}

/// The socket is made bound and not listening, for the namespace
/// holder to listen on, this user's alone; one a namespace holder
/// answers on is left to it.
#[test]
fn the_socket_is_bound_for_the_namespace_holder_and_never_taken_from_one() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/lab/holder.sock");
    let bound = bound_socket(&socket).unwrap();
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let folder = std::fs::metadata(socket.parent().unwrap()).unwrap();
    assert_eq!(folder.permissions().mode() & 0o777, 0o700);
    // Not listening yet: nobody is answered.
    assert!(UnixStream::connect(&socket).is_err());
    rustix::net::listen(&bound, 1).unwrap();
    let refused = bound_socket(&socket).unwrap_err();
    assert!(refused.0.contains("already answers"), "{refused}");
    // Shut down as well as closed: a child another test forks meanwhile
    // holds a copy of the descriptor until it execs, which would keep the
    // socket answering; shutting it down ends it for every copy.
    rustix::net::shutdown(&bound, rustix::net::Shutdown::Both).unwrap();
    drop(bound);
    // Ended: its socket file is replaced.
    bound_socket(&socket).unwrap();
}

/// Both sockets `command` binds reach `serve` on its stdin, whole:
/// what is read back is the same two sockets, in order.
#[test]
fn the_namespace_holders_sockets_reach_it_through_its_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let socket = bound_socket(&dir.path().join("run/lab/holder.sock")).unwrap();
    let inward = bound_socket(&dir.path().join("run/lab/inward.sock")).unwrap();
    let stdin = handed_over([socket.as_fd(), inward.as_fd()]).unwrap();
    let (said, taken) = received(&UnixStream::from(stdin)).unwrap();
    assert_eq!(said, SOCKETS.as_bytes());
    for (sent, got) in [(&socket, &taken[0]), (&inward, &taken[1])] {
        let (sent, got) = (
            rustix::fs::fstat(sent).unwrap(),
            rustix::fs::fstat(got).unwrap(),
        );
        assert_eq!((sent.st_dev, sent.st_ino), (got.st_dev, got.st_ino));
    }
}
