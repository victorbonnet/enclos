//! The relay (design §5, Linux networking): the part of enclos inside a
//! session that listens on the session's own 127.0.0.1 and passes each
//! connection to a Unix socket outside it, and nothing else. It reads and
//! decides nothing: the proxy behind the socket does. [`inward`] is the
//! other way, from the host to a port in a sandbox's network namespace.
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
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::budget::{self, Slot};

pub mod inward;

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

/// The listener for a relay to `socket`, on 127.0.0.1 alone.
pub fn listen(port: u16, socket: &Path) -> Result<TcpListener> {
    // Said now: on the first connection it would reach no one.
    SocketAddr::from_pathname(socket).map_err(|source| Error::RelaySocket {
        path: socket.to_path_buf(),
        source,
    })?;
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|source| Error::RelayListen { port, source })
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
    // Said once until it clears, not for every connection.
    let unreachable = AtomicBool::new(false);
    serve_each(
        || listener.accept().map(|(client, _)| client),
        max,
        move |client: TcpStream| match UnixStream::connect(&socket) {
            Ok(upstream) => {
                unreachable.store(false, Ordering::Relaxed);
                carry(&client, &upstream, limit);
            }
            Err(e) => {
                if !unreachable.swap(true, Ordering::Relaxed) {
                    say(format_args!("cannot reach {}: {e}", socket.display()));
                }
            }
        },
    )
}

/// Hands each connection `accept` gives to `pass`, on a thread of its own,
/// until the process ends, with at most `max` at once: one over that is
/// closed with nothing said to it. Accepting that fails, as when the process
/// is out of descriptors, is tried again after a pause. Each is said once
/// until it clears, not for every connection.
fn serve_each<C: Send + 'static>(
    mut accept: impl FnMut() -> io::Result<C>,
    max: usize,
    pass: impl Fn(C) + Send + Sync + 'static,
) -> ! {
    let pass = Arc::new(pass);
    let open = Arc::new(AtomicUsize::new(0));
    let mut full = false;
    let mut failing = false;
    loop {
        let client = match accept() {
            Ok(client) => client,
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
        let pass = Arc::clone(&pass);
        let started = thread::Builder::new().spawn(move || {
            let _slot = slot;
            pass(client);
        });
        if let Err(e) = started {
            say(format_args!("cannot start a thread for a connection: {e}"));
        }
    }
}

/// A connected stream socket a relay carries: TCP or Unix.
pub(crate) trait Stream: Sync {
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    fn set_write_timeout(&self, limit: Option<Duration>) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn set_write_timeout(&self, limit: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, limit)
    }
}

impl Stream for UnixStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        UnixStream::shutdown(self, how)
    }

    fn set_write_timeout(&self, limit: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, limit)
    }
}

/// Carries both directions of one connection until both have ended. A read
/// has no limit, as a quiet connection is not a stuck one, but a write has
/// `limit`, and so does the upload once the proxy has left.
pub(crate) fn carry<C, U>(client: &C, upstream: &U, limit: Duration)
where
    C: Stream,
    U: Stream,
    for<'a> &'a C: Read + Write,
    for<'a> &'a U: Read + Write,
{
    let _ = client.set_write_timeout(Some(limit));
    let _ = upstream.set_write_timeout(Some(limit));
    let (up_ended, wait_up) = mpsc::channel::<()>();
    thread::scope(|s| {
        let up = thread::Builder::new().spawn_scoped(s, move || {
            let _ended = up_ended;
            copy_through(client, upstream);
            // Ended or failed, the upload ends alone: the proxy may still be
            // answering, as when it refuses a request with the body unread.
            let _ = upstream.shutdown(Shutdown::Write);
        });
        if let Err(e) = up {
            say(format_args!("cannot start a thread for a connection: {e}"));
            return;
        }
        if copy_through(upstream, client) {
            // macOS answers ENOTCONN when the client has closed already,
            // while the upload may still carry its last bytes: ignored.
            let _ = client.shutdown(Shutdown::Write);
            // A read on the client cannot see that the proxy left, so a
            // client that sends nothing more would hold its place.
            let _ = wait_up.recv_timeout(limit);
            let _ = client.shutdown(Shutdown::Both);
        } else {
            // A failed download ends both, waking the upload if it is blocked.
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
        }
    });
}

/// Copies `from` to `to` up to its end of input, and says why it failed
/// unless a peer left. Whether it reached the end.
fn copy_through(mut from: impl Read, mut to: impl Write) -> bool {
    match io::copy(&mut from, &mut to) {
        Ok(_) => true,
        Err(e) => {
            say_lost(&e, &mut io::stderr());
            false
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
