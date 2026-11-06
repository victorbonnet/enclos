//! The relay over a loopback port and a Unix socket in a temporary folder.

mod harness;

use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::{OWN_DESCRIPTORS, connections_for, copy_through, say_lost};
use harness::{LARGE, PATIENCE, Relay, accepted_within, all_of, assert_ends, pattern};

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
    upstream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (wrote, flooded) = mpsc::channel();
    let flood = thread::spawn(move || {
        let chunk = pattern(64 * 1024, 1);
        let mut total = 0;
        // Stops at the end of the room the relay and the sockets leave.
        let stopped = loop {
            match (&upstream).write(&chunk) {
                Ok(read) if total < LARGE => total += read,
                Ok(_) => break None,
                Err(e) => break Some(e.kind()),
            }
        };
        wrote.send((total, stopped)).unwrap();
    });
    let (total, stopped) = flooded.recv_timeout(PATIENCE).unwrap();
    assert!(total < LARGE, "the relay took all {total} bytes");
    assert_eq!(stopped, Some(ErrorKind::WouldBlock));
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
fn an_upstream_gone_frees_the_connections_place() {
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

/// The upload is blocked on an upstream that never reads, so it cannot end
/// by itself: only the failed download can end it.
#[test]
fn a_failed_download_ends_the_upload_and_frees_the_connections_place() {
    let relay = Relay::up_to(1);
    let client = relay.client();
    let upstream = relay.accepted();
    client
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let chunk = pattern(64 * 1024, 6);
    let stopped = loop {
        if let Err(e) = (&client).write_all(&chunk) {
            break e;
        }
    };
    assert_eq!(stopped.kind(), ErrorKind::WouldBlock);
    let _ = client.shutdown(Shutdown::Both);
    drop(client);
    assert_ends(&upstream, &chunk);
    relay.served_again();
}

/// Short, so the tests below see it fire. The tests that must outlast it
/// wait a few times as long.
const SHORT: Duration = Duration::from_millis(300);

#[test]
fn a_client_that_says_nothing_after_upstream_left_frees_its_place() {
    let relay = Relay::limited(1, SHORT);
    let client = relay.client();
    drop(relay.accepted());
    // Told at once; only the limit can end what still reads from it.
    assert_eq!(all_of(&client), b"");
    relay.served_again();
    drop(client);
}

#[test]
fn a_client_that_stops_reading_loses_the_connection_and_frees_its_place() {
    let relay = Relay::limited(1, SHORT);
    let client = relay.client();
    let upstream = relay.accepted();
    let chunk = pattern(64 * 1024, 5);
    assert_ends(&upstream, &chunk);
    relay.served_again();
    drop(client);
}

#[test]
fn a_quiet_connection_outlasts_the_limit() {
    let relay = Relay::limited(1, SHORT);
    let mut client = relay.client();
    let upstream = relay.accepted();
    thread::sleep(SHORT * 3);
    client.write_all(b"ping").unwrap();
    let mut got = [0; 4];
    (&upstream).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    (&upstream).write_all(b"pong").unwrap();
    client.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"pong");
}

/// A proxy refusing a request whose body it did not read: the upload fails,
/// and the refusal comes after. Linux fails a write to a peer that shut its
/// reading at once; macOS may keep it, and passes either way.
#[test]
fn a_failed_upload_leaves_the_answer_on_its_way_to_the_client() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    upstream.shutdown(Shutdown::Read).unwrap();
    client.write_all(b"body").unwrap();
    thread::sleep(Duration::from_millis(200));
    (&upstream).write_all(b"refused").unwrap();
    drop(upstream);
    assert_eq!(all_of(&client), b"refused");
}

/// A client that sent its last bytes and closed both ways: macOS answers
/// ENOTCONN when the relay tells it the download ended, and Linux does not.
/// Either way the upload still carries those bytes to the proxy.
#[test]
fn a_peer_that_cannot_be_told_the_input_ended_does_not_end_the_other_direction() {
    let relay = Relay::start();
    let mut client = relay.client();
    let upstream = relay.accepted();
    // Before anything closes: macOS refuses a timeout once the peer has.
    upstream.set_read_timeout(Some(PATIENCE)).unwrap();
    client.write_all(b"last").unwrap();
    drop(client);
    thread::sleep(Duration::from_millis(200));
    upstream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(all_of(&upstream), b"last");
}

#[test]
fn a_copy_says_whether_it_reached_the_end_of_its_input() {
    let mut sent = Vec::new();
    assert!(copy_through(&b"last"[..], &mut sent));
    assert_eq!(sent, b"last");
    let mut full = [0u8; 2];
    assert!(!copy_through(&b"last"[..], &mut full[..]));
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
fn a_failed_direction_is_said_unless_its_peer_just_left() {
    let said = |kind: ErrorKind| {
        let mut out = Vec::new();
        say_lost(&kind.into(), &mut out);
        String::from_utf8(out).unwrap()
    };
    for left in [
        ErrorKind::ConnectionReset,
        ErrorKind::BrokenPipe,
        ErrorKind::NotConnected,
    ] {
        assert_eq!(said(left), "");
    }
    let timed_out = said(ErrorKind::WouldBlock);
    assert!(
        timed_out.starts_with("enclos relay: lost a connection: "),
        "{timed_out}"
    );
}

#[test]
#[should_panic(expected = "no connection came")]
fn a_connection_that_never_comes_fails_the_test_rather_than_hanging_it() {
    let relay = Relay::start();
    accepted_within(&relay.upstream, Duration::from_millis(50));
}

#[test]
fn the_connection_limit_follows_the_descriptors_and_is_never_none() {
    let connections_for =
        |descriptors| connections_for(crate::net::budget::left_after(descriptors, OWN_DESCRIPTORS));
    assert_eq!(connections_for(Some(256)), 124);
    assert_eq!(connections_for(None), connections_for(Some(1 << 20)));
    assert_eq!(connections_for(None), 508);
    assert_eq!(connections_for(Some(3)), 1);
}
