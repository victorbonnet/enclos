//! What the relay's tests share: a relay serving a loopback port, the
//! Unix socket it passes connections to, and the ends a test holds.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::super::serve_up_to;
use crate::proxy::IDLE_TIMEOUT;

/// Far beyond the sockets' buffers.
pub(super) const LARGE: usize = 64 * 1024 * 1024;

/// How long a test waits for what must happen: long, since a test that
/// passes waits only as long as it takes, and a hang is a failure.
pub(super) const PATIENCE: Duration = Duration::from_secs(60);

pub(super) struct Relay {
    pub(super) port: u16,
    pub(super) upstream: UnixListener,
    pub(super) path: PathBuf,
    _folder: tempfile::TempDir,
}

impl Relay {
    pub(super) fn up_to(max: usize) -> Relay {
        Relay::limited(max, IDLE_TIMEOUT)
    }

    pub(super) fn limited(max: usize, limit: Duration) -> Relay {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let socket = path.clone();
        thread::spawn(move || serve_up_to(listener, &socket, max, limit));
        Relay {
            port,
            upstream,
            path,
            _folder: folder,
        }
    }

    pub(super) fn start() -> Relay {
        Relay::up_to(16)
    }

    pub(super) fn client(&self) -> TcpStream {
        let client = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        client.set_read_timeout(Some(PATIENCE)).unwrap();
        client.set_write_timeout(Some(PATIENCE)).unwrap();
        client
    }

    /// Waits until a new connection gets through, as a place in the limit
    /// frees on the relay's own threads: until then each is closed.
    pub(super) fn served_again(&self) {
        let (done, wait) = mpsc::channel();
        // Dropped when this gives up, which ends the loop below.
        let (_trying, given_up) = mpsc::channel::<()>();
        let port = self.port;
        thread::spawn(move || {
            while given_up.try_recv() == Err(mpsc::TryRecvError::Empty) {
                let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
                let _ = client.write_all(b"x");
                // macOS refuses the option (EINVAL) on a connection already
                // closed both ways, as this one is if it was over the limit;
                // the read below then cannot wait.
                let _ = client.set_read_timeout(Some(PATIENCE));
                if client.read(&mut [0; 1]).unwrap_or(0) == 1 {
                    done.send(()).unwrap();
                    return;
                }
            }
        });
        // Held open until the client has read: closing it with the client's
        // byte unread could reset the connection and lose the answer.
        let upstream = self.accepted();
        (&upstream).write_all(b"y").unwrap();
        wait.recv_timeout(PATIENCE).unwrap();
    }

    /// The upstream end of the connection the relay opens next.
    pub(super) fn accepted(&self) -> UnixStream {
        let conn = accepted_within(&self.upstream, PATIENCE);
        conn.set_read_timeout(Some(PATIENCE)).unwrap();
        conn.set_write_timeout(Some(PATIENCE)).unwrap();
        conn
    }
}

/// The next connection on `listener`. Failing after `patience`, on a thread
/// of its own, as `accept` has no timeout and would hang the test.
pub(super) fn accepted_within(listener: &UnixListener, patience: Duration) -> UnixStream {
    let listener = listener.try_clone().unwrap();
    let (got, wait) = mpsc::channel();
    thread::spawn(move || {
        let _ = got.send(listener.accept());
    });
    let accepted = wait.recv_timeout(patience);
    accepted.expect("no connection came").unwrap().0
}

pub(super) fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
}

/// Writes until the relay ends the connection under `to`, which shows as a
/// reset when what was written is left unread, and as a broken pipe if not.
/// macOS answers a socket the relay already shut down with ENOTCONN, which
/// the relay counts as a peer leaving too.
/// A write that times out instead means nothing ended it.
pub(super) fn assert_ends(mut to: &UnixStream, chunk: &[u8]) {
    let ended = loop {
        if let Err(e) = to.write_all(chunk) {
            break e;
        }
    };
    assert!(
        matches!(
            ended.kind(),
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::NotConnected
        ),
        "{ended}"
    );
}

pub(super) fn all_of(mut from: impl Read) -> Vec<u8> {
    let mut got = Vec::new();
    from.read_to_end(&mut got).unwrap();
    got
}
