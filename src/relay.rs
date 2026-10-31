//! The relay (design §5, Linux networking): the part of enclos inside a
//! session that listens on the session's own 127.0.0.1 and passes each
//! connection to a Unix socket outside it, and nothing else. It reads and
//! decides nothing: the proxy behind the socket does.
//!
//! A connection holds two threads, one per direction, so a direction blocked
//! on a slow reader holds up neither the other direction nor other
//! connections. Nothing is held beyond one read and the kernel's socket
//! buffers, so a slow reader slows its sender. An end of input ends one
//! direction only; a failed direction ends both.
//!
//! It has no idle limit: one that fired on a quiet direction would cut a
//! long download or upload, and the proxy holds the limit on what it serves.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::proxy::Slot;

/// The descriptors a relay keeps for itself: the standard streams, its
/// listener, what the session's launcher left open.
const OWN_DESCRIPTORS: u64 = 8;

/// The most descriptors a relay plans for, as the proxy does: its
/// connections also hold threads, which nothing else bounds.
const MOST_DESCRIPTORS: u64 = 1024;

/// How long to wait before accepting again after accepting failed, such as
/// when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The most connections a relay carries at once in a process limited to
/// `descriptors` (none: no limit). Each holds two; never none.
fn connections_for(descriptors: Option<u64>) -> usize {
    let left = descriptors
        .unwrap_or(MOST_DESCRIPTORS)
        .min(MOST_DESCRIPTORS)
        .saturating_sub(OWN_DESCRIPTORS);
    ((left / 2) as usize).max(1)
}

/// Passes each connection on `listener` to the Unix socket at `socket`,
/// until the process ends. A socket nobody answers on closes the connection
/// and is tried again for the next, so the proxy can restart under a relay.
pub fn serve(listener: TcpListener, socket: &Path) -> ! {
    // The soft limit is the one a descriptor hits: the session's.
    let descriptors = rustix::process::getrlimit(rustix::process::Resource::Nofile).current;
    serve_up_to(listener, socket, connections_for(descriptors))
}

fn serve_up_to(listener: TcpListener, socket: &Path, max: usize) -> ! {
    let socket: Arc<Path> = Arc::from(socket);
    let open = Arc::new(AtomicUsize::new(0));
    // Each said once until it clears, not for every connection.
    let unreachable = Arc::new(AtomicBool::new(false));
    let mut full = false;
    loop {
        let Ok((client, _)) = listener.accept() else {
            thread::sleep(ACCEPT_BACKOFF);
            continue;
        };
        let Some(slot) = Slot::take(&open, max) else {
            if !std::mem::replace(&mut full, true) {
                eprintln!(
                    "enclos relay: {max} connections are open; closing new ones until one ends"
                );
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
                    carry(&client, &upstream);
                }
                Err(e) => {
                    if !unreachable.swap(true, Ordering::Relaxed) {
                        eprintln!("enclos relay: cannot reach {}: {e}", socket.display());
                    }
                }
            }
        });
        if let Err(e) = started {
            eprintln!("enclos relay: cannot start a thread for a connection: {e}");
        }
    }
}

/// Carries both directions of one connection until both have ended.
fn carry(client: &TcpStream, upstream: &UnixStream) {
    // Wakes the other direction, which may be blocked.
    let end_both = || {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
    };
    thread::scope(|s| {
        let up = thread::Builder::new().spawn_scoped(s, || {
            forward(
                client,
                upstream,
                || upstream.shutdown(Shutdown::Write),
                end_both,
            )
        });
        if let Err(e) = up {
            eprintln!("enclos relay: cannot start a thread for a connection: {e}");
            return;
        }
        forward(
            upstream,
            client,
            || client.shutdown(Shutdown::Write),
            end_both,
        );
    });
}

/// Copies one direction to its end of input, then tells the other side with
/// `done`; `failed` runs when either goes wrong.
fn forward(
    mut from: impl Read,
    mut to: impl Write,
    done: impl FnOnce() -> io::Result<()>,
    failed: impl FnOnce(),
) {
    if io::copy(&mut from, &mut to).and_then(|_| done()).is_err() {
        failed();
    }
}

#[cfg(test)]
mod tests;
