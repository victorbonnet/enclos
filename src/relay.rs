//! The relay (design §5, Linux networking): the part of enclos inside a
//! session that listens on the session's own 127.0.0.1 and passes each
//! connection to a Unix socket outside it, and nothing else. It reads and
//! decides nothing: the proxy behind the socket does.
//!
//! A connection holds two threads, one per direction, so a direction blocked
//! on a slow reader holds up neither the other direction nor other
//! connections. Nothing is held beyond one read and the kernel's socket
//! buffers, so a slow reader slows its sender. An end of input ends one
//! direction only, and so does a failed upload, as the proxy may still be
//! answering; a failed download ends both.
//!
//! A quiet connection stays: a limit on reading would cut a long download or
//! upload, and the proxy holds the limit on what it serves. The relay holds
//! one on what the proxy cannot see: a write that moves nothing, and a client
//! that sends nothing more after the proxy has left.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use crate::net::budget::{self, Slot};

/// The descriptors a relay keeps for itself: the standard streams, its
/// listener, what the session's launcher left open.
const OWN_DESCRIPTORS: u64 = 8;

/// How long to wait before accepting again after accepting failed, such as
/// when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Says `what` on stderr, if anyone is there: `eprintln!` panics on a closed
/// pipe, and the accepting thread is the relay.
fn say(what: std::fmt::Arguments) {
    let _ = writeln!(io::stderr(), "enclos relay: {what}");
}

/// The most connections a relay carries at once with `left` descriptors to
/// share. Each holds two; never none.
fn connections_for(left: u64) -> usize {
    ((left / 2) as usize).max(1)
}

/// Passes each connection on `listener` to the Unix socket at `socket`,
/// until the process ends. A socket nobody answers on closes the connection
/// and is tried again for the next, so the proxy can restart under a relay.
pub fn serve(listener: TcpListener, socket: &Path) -> ! {
    serve_up_to(
        listener,
        socket,
        connections_for(budget::descriptors_to_share(OWN_DESCRIPTORS)),
        crate::proxy::IDLE_TIMEOUT,
    )
}

fn serve_up_to(listener: TcpListener, socket: &Path, max: usize, limit: Duration) -> ! {
    let socket: Arc<Path> = Arc::from(socket);
    let open = Arc::new(AtomicUsize::new(0));
    // Each said once until it clears, not for every connection.
    let unreachable = Arc::new(AtomicBool::new(false));
    let mut full = false;
    let mut failing = false;
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(e) => {
                if !std::mem::replace(&mut failing, true) {
                    say(format_args!("cannot accept a connection: {e}"));
                }
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        failing = false;
        let Some(slot) = Slot::take(&open, max) else {
            if !std::mem::replace(&mut full, true) {
                say(format_args!(
                    "{max} connections are open; closing new ones until one ends"
                ));
            }
            continue;
        };
        full = false;
        let socket = Arc::clone(&socket);
        let unreachable = Arc::clone(&unreachable);
        let started = thread::Builder::new().spawn(move || {
            let _slot = slot;
            match UnixStream::connect(&socket) {
                Ok(upstream) => {
                    unreachable.store(false, Ordering::Relaxed);
                    carry(&client, &upstream, limit);
                }
                Err(e) => {
                    if !unreachable.swap(true, Ordering::Relaxed) {
                        say(format_args!("cannot reach {}: {e}", socket.display()));
                    }
                }
            }
        });
        if let Err(e) = started {
            say(format_args!("cannot start a thread for a connection: {e}"));
        }
    }
}

/// Carries both directions of one connection until both have ended. A read
/// has no limit, as a quiet connection is not a stuck one, but a write has
/// `limit`, and so does the upload once the proxy has left.
fn carry(client: &TcpStream, upstream: &UnixStream, limit: Duration) {
    let _ = client.set_write_timeout(Some(limit));
    let _ = upstream.set_write_timeout(Some(limit));
    // Wakes the other direction, which may be blocked.
    let end_both = || {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
    };
    let (up_ended, wait_up) = mpsc::channel::<()>();
    thread::scope(|s| {
        // A failed upload ends the upload alone: the proxy may be answering,
        // as when it refuses a request and closes with the body unread.
        let up = thread::Builder::new().spawn_scoped(s, move || {
            let _ended = up_ended;
            pass_on(
                client,
                upstream,
                || upstream.shutdown(Shutdown::Write),
                || {
                    let _ = upstream.shutdown(Shutdown::Write);
                },
            )
        });
        if let Err(e) = up {
            say(format_args!("cannot start a thread for a connection: {e}"));
            return;
        }
        pass_on(
            upstream,
            client,
            || {
                let told = client.shutdown(Shutdown::Write);
                // A read on the client cannot see that the proxy left, so a
                // client that sends nothing more would hold its place.
                let _ = wait_up.recv_timeout(limit);
                let _ = client.shutdown(Shutdown::Both);
                told
            },
            end_both,
        );
    });
}

/// Copies one direction to its end of input, then tells the other side with
/// `done`; `failed` runs when the copy goes wrong. A `done` that fails ends
/// nothing: macOS answers ENOTCONN when that side has closed already, while
/// the other direction may still carry the last of what it sent.
fn pass_on(
    mut from: impl Read,
    mut to: impl Write,
    done: impl FnOnce() -> io::Result<()>,
    failed: impl FnOnce(),
) {
    match io::copy(&mut from, &mut to) {
        Ok(_) => {
            let _ = done();
        }
        Err(e) => {
            say_lost(&e, &mut io::stderr());
            failed();
        }
    }
}

/// Says why a direction failed, on `to`, unless it is a peer leaving, which
/// is how many connections end.
fn say_lost(e: &io::Error, to: &mut impl Write) {
    if !matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
    ) {
        let _ = writeln!(to, "enclos relay: lost a connection: {e}");
    }
}

#[cfg(test)]
mod tests;
