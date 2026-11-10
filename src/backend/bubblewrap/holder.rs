//! The namespace holder (ADR 0039; design §5, A session's namespaces): the
//! process that keeps a bubblewrap sandbox's one network namespace in being,
//! serves the sandbox's relay to its proxy on 127.0.0.1 there, and hands the
//! namespace to each session that joins it.
//!
//! Four hidden commands make it up. `enclos holder run <sandbox>`, which the
//! service manager runs, binds the namespace holder's two sockets in the
//! host-only `run/<sandbox>/` and runs bubblewrap ([`command`]), which
//! makes user, PID and network namespaces and runs `enclos holder serve` in
//! them ([`serve`]). One hands out the namespaces; on the other, its way
//! in, the namespace holder relays the host's connections to a port in its
//! network namespace (ADR 0040; `relay::inward`). Every session starts
//! with `enclos holder join` ([`join`]), which runs `enclos holder enter`
//! ([`enter`]): that asks the namespace holder for its namespaces, enters
//! its user namespace then its network namespace, as `nsenter` would, and
//! becomes the session's bubblewrap, which makes the session's own user,
//! PID and IPC namespaces inside them. The descriptors close on `exec`, so
//! no session holds one. `join` stays on the host, in none of the
//! sandbox's namespaces, and waits for bubblewrap: it starts `enter` again
//! when bubblewrap's setup met a mount that changed, as `holder run` does
//! with its own bubblewrap (`setup`).
//!
//! The namespace holder runs without `--dev /dev`: bubblewrap nests a second
//! user namespace for it, which would not own the network namespace, and no
//! session could then join (EPERM).

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::ops::RangeInclusive;
use std::path::Path;
use std::process::{Command, ExitStatus};

use super::setup;

/// The arguments of `enclos` that start a session joined to the namespace
/// holder listening on `socket`: what follows them is the command it runs,
/// the session's bubblewrap.
pub(super) fn join_args(socket: &Path) -> Vec<OsString> {
    holder_args("join", socket)
}

/// The arguments of `enclos` that enter the namespaces of the namespace
/// holder listening on `socket`: what follows them is the command it
/// becomes.
fn enter_args(socket: &Path) -> Vec<OsString> {
    holder_args("enter", socket)
}

fn holder_args(verb: &str, socket: &Path) -> Vec<OsString> {
    vec![
        "holder".into(),
        verb.into(),
        "--socket".into(),
        socket.into(),
        "--".into(),
    ]
}

/// Starts a session of the sandbox whose namespace holder listens on
/// `socket`: runs `enclos holder enter` (`enclos` being this program),
/// which enters the namespace holder's namespaces and becomes `command`,
/// the session's bubblewrap, and waits for it, with `stderr` as the
/// session's. It is started again while bubblewrap's setup meets a mount
/// that changed (`setup`). How the last start ended, or why it could not
/// start.
pub fn join(
    enclos: &Path,
    socket: &Path,
    command: &[OsString],
    stderr: &File,
) -> io::Result<ExitStatus> {
    setup::run(
        || {
            let mut enter = Command::new(enclos);
            enter.args(enter_args(socket)).args(command);
            Ok(enter)
        },
        stderr,
        &setup::PAUSES,
    )
}

/// What a namespace holder says to each connection besides its descriptors:
/// the ports a bind on port 0 lands in, in its namespace, as
/// `ip_local_port_range` writes them. Pure, so tested on every system; the
/// namespace holder runs on Linux alone.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn message(first: u16, last: u16) -> String {
    format!("{first} {last}")
}

/// The ephemeral ports in a namespace holder's message, which holds two
/// ports in order and nothing else.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ports_in(message: &[u8]) -> Option<RangeInclusive<u16>> {
    let text = std::str::from_utf8(message).ok()?;
    let mut words = text.split_whitespace();
    let (first, last): (u16, u16) = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
    (words.next().is_none() && first <= last).then_some(first..=last)
}

#[cfg(target_os = "linux")]
pub use linux::{Answer, ask, command, enter, serve};

#[cfg(all(test, target_os = "linux"))]
pub(crate) use linux::stand_in;

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fs::{DirBuilder, File};
    use std::io::{self, IoSlice, IoSliceMut};
    use std::mem::MaybeUninit;
    use std::ops::RangeInclusive;
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use rustix::net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags,
        SocketType,
    };
    use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

    use super::{message, ports_in};
    use crate::backend::{SandboxContext, WrapError};

    /// bubblewrap's arguments for the namespace holder: user, PID and network
    /// namespaces of its own, ended with the process the service manager
    /// runs, and the host's files read-only, with a `/proc` of its PID
    /// namespace, where it opens its namespaces. No `--dev /dev` (above).
    const BUBBLEWRAP: &[&str] = &[
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ];

    /// How long a namespace holder has to answer a connection.
    const ANSWER: Duration = Duration::from_secs(5);

    /// How many connections wait for the namespace holder at once.
    const BACKLOG: i32 = 64;

    /// What the message that hands the namespace holder its sockets says.
    const SOCKETS: &str = "sockets";

    /// The command that becomes the namespace holder of `ctx`'s sandbox:
    /// bubblewrap running `enclos holder serve` in namespaces of its own,
    /// with the holder's socket and its way in bound, and handed over on its
    /// stdin. The relay inside serves the sandbox's proxy port, and passes
    /// each connection to the proxy's socket. The command starts with an
    /// empty environment: the namespace holder reads no variable.
    pub fn command(
        bwrap: &Path,
        enclos: &Path,
        ctx: &SandboxContext,
    ) -> Result<Command, WrapError> {
        let socket = bound_socket(&ctx.holder_socket)?;
        let inward = bound_socket(&ctx.inward_socket)?;
        let sockets = handed_over([socket.as_fd(), inward.as_fd()])?;
        let mut command = Command::new(bwrap);
        command
            .env_clear()
            .args(BUBBLEWRAP)
            .arg("--")
            .arg(enclos)
            .args(["holder", "serve", "--port"])
            .arg(ctx.proxy_port.to_string())
            .arg("--proxy")
            .arg(&ctx.proxy_socket)
            .stdin(Stdio::from(sockets));
        Ok(command)
    }

    /// One end of a pair of connected sockets, holding `sockets` in one
    /// message for whoever reads it: how the namespace holder gets both of
    /// its sockets on its stdin.
    fn handed_over(sockets: [BorrowedFd<'_>; 2]) -> Result<OwnedFd, WrapError> {
        let failed = |e: &dyn std::fmt::Display| {
            WrapError(format!("cannot hand the namespace holder its sockets: {e}"))
        };
        let (ours, theirs) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|e| failed(&e))?;
        hand_out(&UnixStream::from(ours), SOCKETS, sockets).map_err(|e| failed(&e))?;
        Ok(theirs)
    }

    /// A Unix socket bound at `path`, in a folder this user alone reaches,
    /// and not listening yet: the namespace holder listens on it from inside
    /// its namespaces, so the holder socket's peer credentials name that
    /// process, whose `/proc/<pid>/net` the host reads. One that a namespace holder
    /// still answers on is refused, as replacing that namespace holder would
    /// split the sandbox; one left by a namespace holder that ended goes.
    fn bound_socket(path: &Path) -> Result<OwnedFd, WrapError> {
        let failed = |what: &str, e: &dyn std::fmt::Display| {
            WrapError(format!(
                "cannot {what} the namespace holder's socket {}: {e}",
                path.display()
            ))
        };
        if let Some(folder) = path.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(folder)
                .map_err(|e| failed("make the folder of", &e))?;
        }
        if UnixStream::connect(path).is_ok() {
            return Err(WrapError(format!(
                "a namespace holder already answers on {}: a second one would split the sandbox's sessions between two network namespaces",
                path.display()
            )));
        }
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                return Err(failed("remove the old", &e));
            }
            _ => {}
        }
        let address = SocketAddrUnix::new(path).map_err(|e| failed("name", &e))?;
        let socket = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|e| failed("make", &e))?;
        rustix::net::bind(&socket, &address).map_err(|e| failed("bind", &e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| failed("restrict", &e))?;
        Ok(socket)
    }

    /// Serves as the namespace holder, in the namespaces bubblewrap made,
    /// on the two sockets `command` bound and handed over in `sockets`:
    /// runs the relay from 127.0.0.1 at `port` to the proxy's socket at
    /// `proxy`, and the relay from the host on its way in, and hands each
    /// connection to its socket its user and network namespaces, with its
    /// namespace's ephemeral ports. Returns only what stopped it.
    pub fn serve(sockets: OwnedFd, port: u16, proxy: &Path) -> String {
        if let Err(e) = crate::backend::bubblewrap::setup::done() {
            return format!("cannot take its stderr back from bubblewrap: {e}");
        }
        match serving(sockets, port, proxy) {
            Ok(never) => match never {},
            Err(why) => why,
        }
    }

    fn serving(
        sockets: OwnedFd,
        port: u16,
        proxy: &Path,
    ) -> Result<std::convert::Infallible, String> {
        let unread = |why: &dyn std::fmt::Display| {
            format!("cannot take the namespace holder's sockets from its stdin: {why}")
        };
        let sockets = UnixStream::from(sockets);
        sockets
            .set_read_timeout(Some(ANSWER))
            .map_err(|e| unread(&e))?;
        let [socket, inward] = received(&sockets).map_err(|why| unread(&why))?.1;
        // Here, so the socket's peer credentials are this process's.
        rustix::net::listen(&socket, BACKLOG)
            .map_err(|e| format!("cannot listen on the namespace holder's socket: {e}"))?;
        rustix::net::listen(&inward, BACKLOG)
            .map_err(|e| format!("cannot listen on the namespace holder's way in: {e}"))?;
        let listener = UnixListener::from(socket);
        let open = |kind: &str| {
            File::open(format!("/proc/self/ns/{kind}"))
                .map_err(|e| format!("cannot open its own {kind} namespace: {e}"))
        };
        let (user, net) = (open("user")?, open("net")?);
        let (first, last) = crate::lifecycle::proc::ephemeral_ports()?;
        let said = message(first, last);
        let relay = crate::relay::listen(port, proxy).map_err(|e| e.to_string())?;
        let proxy = proxy.to_owned();
        std::thread::Builder::new()
            .name("relay".to_owned())
            .spawn(move || crate::relay::serve(relay, &proxy))
            .map_err(|e| format!("cannot start the relay: {e}"))?;
        let inward = UnixListener::from(inward);
        std::thread::Builder::new()
            .name("inward".to_owned())
            .spawn(move || crate::relay::inward::serve(inward))
            .map_err(|e| format!("cannot start the relay from the host: {e}"))?;
        let mut failing = false;
        loop {
            match listener.accept() {
                Ok((connection, _)) => {
                    failing = false;
                    // One that left before its answer gets none; the next is
                    // served all the same.
                    let _ = hand_out(&connection, &said, [user.as_fd(), net.as_fd()]);
                }
                Err(e) => {
                    if !std::mem::replace(&mut failing, true) {
                        eprintln!("enclos holder: cannot accept a connection: {e}");
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Sends `said` to `connection`, with `namespaces` as descriptors, in one
    /// message.
    fn hand_out(
        connection: &UnixStream,
        said: &str,
        namespaces: [BorrowedFd<'_>; 2],
    ) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&namespaces)) {
            return Err(io::Error::other("the descriptors do not fit their buffer"));
        }
        rustix::net::sendmsg(
            connection,
            &[IoSlice::new(said.as_bytes())],
            &mut control,
            SendFlags::NOSIGNAL,
        )?;
        Ok(())
    }

    /// What a namespace holder answered.
    pub struct Answer {
        /// Its pid as this process sees it, from the socket's peer
        /// credentials.
        pub pid: u32,
        /// The ports a bind on port 0 lands in, in its namespace.
        pub ephemeral: RangeInclusive<u16>,
        /// Its user namespace, then its network namespace, each closed on
        /// `exec`.
        pub namespaces: [OwnedFd; 2],
    }

    /// Asks the namespace holder on `socket` for its namespaces.
    pub fn ask(socket: &Path) -> Result<Answer, String> {
        let at = socket.display();
        let stream = UnixStream::connect(socket)
            .map_err(|e| format!("no namespace holder answers on {at}: {e}"))?;
        let unread = |e: &dyn std::fmt::Display| {
            format!("cannot read the namespace holder's answer on {at}: {e}")
        };
        stream
            .set_read_timeout(Some(ANSWER))
            .map_err(|e| unread(&e))?;
        let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|e| unread(&e))?;
        let (said, namespaces) = received(&stream).map_err(|why| unread(&why))?;
        let ephemeral = ports_in(&said).ok_or_else(|| {
            format!(
                "the namespace holder on {at} answered `{}`, not its ephemeral ports",
                String::from_utf8_lossy(&said)
            )
        })?;
        Ok(Answer {
            pid: peer.pid.as_raw_nonzero().get().unsigned_abs(),
            ephemeral,
            namespaces,
        })
    }

    /// What [`hand_out`] sent on `stream`: its words, and its two
    /// descriptors, closed on `exec`. Any other count is refused.
    fn received(stream: &UnixStream) -> Result<(Vec<u8>, [OwnedFd; 2]), String> {
        let mut said = [0u8; 64];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = rustix::net::recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut said)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(|e| e.to_string())?;
        let mut fds: Vec<OwnedFd> = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(sent) = message {
                fds.extend(sent);
            }
        }
        if received.flags.contains(ReturnFlags::CTRUNC) {
            return Err("more than two descriptors came".to_owned());
        }
        let count = fds.len();
        let fds: [OwnedFd; 2] = fds
            .try_into()
            .map_err(|_| format!("{count} descriptors came, not two"))?;
        Ok((said[..received.bytes.min(said.len())].to_vec(), fds))
    }

    /// Enters the namespaces of the namespace holder on `socket` the
    /// `nsenter` way: its user namespace, which gives this process every
    /// capability there, then its network namespace, which that user
    /// namespace owns, then becomes `command`. Only a process with one
    /// thread may enter a user namespace, so this runs before anything
    /// starts a thread. Returns only what stopped it, and runs nothing then.
    pub fn enter(socket: &Path, command: &[OsString]) -> String {
        let Some((program, args)) = command.split_first() else {
            return "no command to run".to_owned();
        };
        let [user, net] = match ask(socket) {
            Ok(answer) => answer.namespaces,
            Err(why) => return why,
        };
        let entered = move_into_link_name_space(user.as_fd(), Some(LinkNameSpaceType::User))
            .map_err(|e| format!("cannot enter the namespace holder's user namespace: {e}"))
            .and_then(|()| {
                move_into_link_name_space(net.as_fd(), Some(LinkNameSpaceType::Network)).map_err(
                    |e| format!("cannot enter the namespace holder's network namespace: {e}"),
                )
            });
        if let Err(why) = entered {
            return why;
        }
        drop((user, net));
        let e = Command::new(program).args(args).exec();
        format!("cannot run {}: {e}", program.to_string_lossy())
    }

    /// A namespace holder for tests, outside any namespace: it hands each
    /// connection on `socket` this process's own namespaces, with `ports`.
    #[cfg(test)]
    pub(crate) fn stand_in(socket: &Path, ports: (u16, u16)) -> std::thread::JoinHandle<()> {
        let _ = std::fs::remove_file(socket);
        if let Some(folder) = socket.parent() {
            std::fs::create_dir_all(folder).unwrap();
        }
        let listener = UnixListener::bind(socket).unwrap();
        let user = File::open("/proc/self/ns/user").unwrap();
        let net = File::open("/proc/self/ns/net").unwrap();
        let said = message(ports.0, ports.1);
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                let Ok(connection) = connection else {
                    return;
                };
                let _ = hand_out(&connection, &said, [user.as_fd(), net.as_fd()]);
            }
        })
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ports_are_two_in_order_and_nothing_else() {
        assert_eq!(
            ports_in(message(32768, 60999).as_bytes()),
            Some(32768..=60999)
        );
        for odd in ["", "32768", "60999 32768", "1 2 3", "a b", "1 70000"] {
            assert_eq!(ports_in(odd.as_bytes()), None, "{odd}");
        }
    }

    #[test]
    fn a_session_joins_with_the_namespace_holders_socket_then_its_command() {
        let args = join_args(Path::new("/data/enclos/run/lab/holder.sock"));
        assert_eq!(
            args,
            [
                "holder",
                "join",
                "--socket",
                "/data/enclos/run/lab/holder.sock",
                "--"
            ]
        );
    }

    /// `join` runs `enclos holder enter` with the socket and the session's
    /// bubblewrap, and ends as it does: a stand-in for enclos says what it
    /// was given and exits 3.
    #[test]
    fn a_join_runs_enter_with_the_sessions_bubblewrap_and_ends_as_it_does() {
        let dir = tempfile::tempdir().unwrap();
        let enclos = dir.path().join("enclos");
        crate::test_scripts::write_script(&enclos, "echo \"$@\" >&2\nexit 3");
        let stderr = File::create(dir.path().join("stderr")).unwrap();
        let socket = Path::new("/data/enclos/run/lab/holder.sock");
        let bwrap: Vec<OsString> = vec!["/usr/bin/bwrap".into(), "--die-with-parent".into()];
        let status = join(&enclos, socket, &bwrap, &stderr).unwrap();
        assert_eq!(status.code(), Some(3));
        let said = std::fs::read_to_string(dir.path().join("stderr")).unwrap();
        assert_eq!(
            said,
            "holder enter --socket /data/enclos/run/lab/holder.sock -- /usr/bin/bwrap --die-with-parent\n"
        );
    }
}
