//! The relay over a loopback port and a Unix socket in a temporary folder.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::{connections_for, pass_on, serve_up_to};

/// Far beyond the sockets' buffers.
const LARGE: usize = 64 * 1024 * 1024;

/// How long a test waits for what must happen: long, since a test that
/// passes waits only as long as it takes, and a hang is a failure.
const PATIENCE: Duration = Duration::from_secs(60);

struct Relay {
    port: u16,
    upstream: UnixListener,
    path: PathBuf,
    _folder: tempfile::TempDir,
}

impl Relay {
    fn up_to(max: usize) -> Relay {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("proxy.sock");
        let upstream = UnixListener::bind(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let socket = path.clone();
        thread::spawn(move || serve_up_to(listener, &socket, max));
        Relay {
            port,
            upstream,
            path,
            _folder: folder,
        }
    }

    fn start() -> Relay {
        Relay::up_to(16)
    }

    fn client(&self) -> TcpStream {
        let client = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        client.set_read_timeout(Some(PATIENCE)).unwrap();
        client.set_write_timeout(Some(PATIENCE)).unwrap();
        client
    }

    /// Waits until a new connection gets through, as a place in the limit
    /// frees on the relay's own threads: until then each is closed.
    fn served_again(&self) {
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
    fn accepted(&self) -> UnixStream {
        let conn = accepted_within(&self.upstream, PATIENCE);
        conn.set_read_timeout(Some(PATIENCE)).unwrap();
        conn.set_write_timeout(Some(PATIENCE)).unwrap();
        conn
    }
}

/// The next connection on `listener`. Failing after `patience`, on a thread
/// of its own, as `accept` has no timeout and would hang the test.
fn accepted_within(listener: &UnixListener, patience: Duration) -> UnixStream {
    let listener = listener.try_clone().unwrap();
    let (got, wait) = mpsc::channel();
    thread::spawn(move || {
        let _ = got.send(listener.accept());
    });
    let accepted = wait.recv_timeout(patience);
    accepted.expect("no connection came").unwrap().0
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ seed).collect()
}

/// `len` bytes of `chunk` over and over.
fn pattern_of(chunk: &[u8], len: usize) -> Vec<u8> {
    chunk.iter().copied().cycle().take(len).collect()
}

fn all_of(mut from: impl Read) -> Vec<u8> {
    let mut got = Vec::new();
    from.read_to_end(&mut got).unwrap();
    got
}

#[test]
fn a_large_transfer_both_ways_at_once_arrives_whole() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    // An echo that writes each chunk back before it reads the next, as a
    // server that answers while still reading does: the relay must keep the
    // answers moving while its other direction is blocked.
    let echo = thread::spawn(move || {
        let (mut from, mut to) = (&upstream, &upstream);
        let mut chunk = vec![0; 64 * 1024];
        loop {
            match from.read(&mut chunk).unwrap() {
                0 => break,
                read => to.write_all(&chunk[..read]).unwrap(),
            }
        }
        upstream.shutdown(Shutdown::Write).unwrap();
    });
    let sent = pattern(LARGE, 0);
    let expected = sent.clone();
    let writer = client.try_clone().unwrap();
    let write = thread::spawn(move || {
        (&writer).write_all(&sent).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
    });
    let got = all_of(&mut client);
    write.join().unwrap();
    echo.join().unwrap();
    assert!(
        got == expected,
        "{} of {} bytes, or changed",
        got.len(),
        LARGE
    );
}

#[test]
fn a_client_done_sending_still_gets_its_answer() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    client.write_all(b"request").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(all_of(&upstream), b"request");
    (&upstream).write_all(b"answer").unwrap();
    drop(upstream);
    assert_eq!(all_of(&client), b"answer");
}

#[test]
fn an_upstream_done_sending_still_gets_the_clients_bytes() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    (&upstream).write_all(b"go ahead").unwrap();
    upstream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(all_of(&client), b"go ahead");
    client.write_all(b"still here").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(all_of(&upstream), b"still here");
}

#[test]
fn a_client_that_stops_reading_holds_up_no_other_connection() {
    let relay = Relay::start();
    let stalled = relay.client();
    let upstream = relay.accepted();
    let flood = thread::spawn(move || {
        let chunk = pattern(64 * 1024, 1);
        // Ends when the test's end closes the stalled client.
        while (&upstream).write_all(&chunk).is_ok() {}
    });
    let mut other = relay.client();
    let answering = relay.accepted();
    other.write_all(b"ping").unwrap();
    let mut got = [0; 4];
    (&answering).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    (&answering).write_all(b"pong").unwrap();
    other.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"pong");
    drop(stalled);
    flood.join().unwrap();
}

#[test]
fn a_failed_direction_ends_the_other_and_frees_the_connections_place() {
    let relay = Relay::up_to(1);
    let client = relay.client();
    let upstream = relay.accepted();
    // The client sends past every buffer into an upstream that never reads,
    // so the relay is blocked writing upstream, and blocked reading it the
    // other way; then upstream goes away.
    let writer = client.try_clone().unwrap();
    let write = thread::spawn(move || {
        let chunk = pattern(64 * 1024, 2);
        while (&writer).write_all(&chunk).is_ok() {}
    });
    thread::sleep(Duration::from_millis(200));
    drop(upstream);
    write.join().unwrap();
    // The client is still open: only the relay can have freed the place.
    relay.served_again();
    drop(client);
}

/// A proxy refusing a request whose body it did not read: the upload fails
/// on a closed socket while the refusal is still on its way down.
#[test]
fn a_failed_upload_leaves_the_answer_on_its_way_to_the_client() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    let writer = client.try_clone().unwrap();
    let write = thread::spawn(move || {
        let chunk = pattern(64 * 1024, 3);
        while (&writer).write_all(&chunk).is_ok() {}
    });
    // The client reads nothing yet, so the relay stops on it with the rest
    // of the answer still in the socket when upstream closes.
    upstream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let chunk = pattern(64 * 1024, 4);
    let mut answered = 0;
    let stopped = loop {
        match (&upstream).write(&chunk) {
            Ok(wrote) => answered += wrote,
            Err(e) => break e,
        }
        assert!(answered < LARGE, "nothing held the answer back");
    };
    assert_eq!(stopped.kind(), ErrorKind::WouldBlock);
    drop(upstream);
    let mut got = vec![0; answered];
    client.read_exact(&mut got).unwrap();
    assert!(got == pattern_of(&chunk, answered), "the answer changed");
    write.join().unwrap();
}

/// macOS answers ENOTCONN to telling a peer that has closed, and Linux does
/// not: the other direction may still be carrying that peer's last bytes.
#[test]
fn a_peer_that_cannot_be_told_the_input_ended_does_not_end_the_other_direction() {
    let mut sent = Vec::new();
    pass_on(
        &b"last"[..],
        &mut sent,
        || Err(ErrorKind::NotConnected.into()),
        || panic!("the other direction was ended"),
    );
    assert_eq!(sent, b"last");
}

#[test]
fn a_socket_nobody_answers_on_closes_the_client_and_is_tried_again() {
    let relay = Relay::start();
    std::fs::remove_file(&relay.path).unwrap();
    let client = relay.client();
    assert_eq!(all_of(&client), b"");
    let upstream = UnixListener::bind(&relay.path).unwrap();
    let mut client = relay.client();
    client.write_all(b"back").unwrap();
    let conn = accepted_within(&upstream, PATIENCE);
    let mut got = [0; 4];
    (&conn).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"back");
}

#[test]
fn a_connection_over_the_limit_is_closed_and_its_place_comes_back() {
    let relay = Relay::up_to(1);
    let first = relay.client();
    let upstream = relay.accepted();
    let over = relay.client();
    assert_eq!(all_of(&over), b"");

    drop(first);
    drop(upstream);
    relay.served_again();
}

#[test]
#[should_panic(expected = "no connection came")]
fn a_connection_that_never_comes_fails_the_test_rather_than_hanging_it() {
    let relay = Relay::start();
    accepted_within(&relay.upstream, Duration::from_millis(50));
}

#[test]
fn the_connection_limit_follows_the_descriptors_and_is_never_none() {
    assert_eq!(connections_for(Some(256)), 124);
    assert_eq!(connections_for(None), connections_for(Some(1 << 20)));
    assert_eq!(connections_for(None), 508);
    assert_eq!(connections_for(Some(3)), 1);
}
