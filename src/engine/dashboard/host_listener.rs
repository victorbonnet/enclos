//! The dashboard's listener (ADR 0040): the host's 127.0.0.1 at a
//! sandbox's reserved port, open to the user running `enclos dashboard`
//! alone. Every user of the host shares loopback, and a runtime's dashboard
//! gives its page, with its session token, to whoever connects, so the
//! owner of each connection's client socket is read from the kernel's
//! tables, and another user's connection, or one whose owner cannot be
//! told, is closed before a byte is read or passed on. Each other one goes
//! to the dashboard's port in the sandbox's network namespace, through the
//! namespace holder's way in. The address and the check are fixed here,
//! with no setting.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::net::budget::Slot;
use crate::relay::{carry, inward::WayIn};

/// How often the listener looks for a connection, and whether to close.
const POLL: Duration = Duration::from_millis(20);

/// The most connections it carries at once: a browser opens a few.
const CONNECTIONS: usize = 64;

/// Who owns the client socket of a connection, from its client's and its
/// server's addresses: `None` when that cannot be told.
pub(super) type Owner = fn(SocketAddr, SocketAddr) -> Option<u32>;

/// The owner as this host's tables say, in this process's network
/// namespace, where the listener is.
pub(super) fn owner_on_host(client: SocketAddr, server: SocketAddr) -> Option<u32> {
    crate::lifecycle::proc::tcp_client_owner(client, server)
        .ok()
        .flatten()
}

/// The listener while it serves: dropped, it stops accepting and closes.
/// Connections it passed on run until either end closes them.
pub(super) struct Listening {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Opens 127.0.0.1 at `port` to `user` alone, as `owner` tells each
/// connection's: each of theirs goes to `service` in the sandbox's network
/// namespace through `way_in`.
pub(super) fn open(
    port: u16,
    user: u32,
    owner: Owner,
    way_in: WayIn,
    service: u16,
) -> io::Result<Listening> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    // Polled, so that closing it needs no connection to wake it.
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("dashboard".to_owned())
        .spawn(move || {
            let door = Door {
                user,
                owner,
                way_in,
                service,
            };
            door.serve(&listener, &stopped);
        })?;
    Ok(Listening {
        stop,
        thread: Some(thread),
    })
}

/// What each connection is checked against and passed to.
struct Door {
    user: u32,
    owner: Owner,
    way_in: WayIn,
    service: u16,
}

impl Door {
    fn serve(self, listener: &TcpListener, stop: &AtomicBool) {
        let door = Arc::new(self);
        let open = Arc::new(AtomicUsize::new(0));
        // Each refused owner said once, not for every connection.
        let mut refused = BTreeSet::new();
        while !stop.load(Ordering::Relaxed) {
            let (client, peer) = match listener.accept() {
                Ok(accepted) => accepted,
                // None waiting, or none can be taken now (out of descriptors).
                Err(_) => {
                    thread::sleep(POLL);
                    continue;
                }
            };
            let owner = client
                .local_addr()
                .ok()
                .and_then(|server| (door.owner)(peer, server));
            if owner != Some(door.user) {
                // Dropped unread: closed before a byte reaches the service.
                drop(client);
                if refused.insert(owner) {
                    crate::notes::say(&refusal(owner, door.user));
                }
                continue;
            }
            // Over the limit, closed with nothing said: a browser opens it again.
            let Some(slot) = Slot::take(&open, CONNECTIONS) else {
                continue;
            };
            let door = Arc::clone(&door);
            let _ = thread::Builder::new().spawn(move || {
                let _slot = slot;
                door.pass(client);
            });
        }
    }

    /// Carries `client` to the dashboard's port, or closes it when that
    /// cannot be reached.
    fn pass(&self, client: TcpStream) {
        // A socket accepted from a polled listener is polled too on macOS.
        if client.set_nonblocking(false).is_err() {
            return;
        }
        if let Ok(upstream) = self.way_in.connect(self.service) {
            carry(&client, &upstream, crate::proxy::IDLE_TIMEOUT);
        }
    }
}

/// What is said of a connection closed for its owner.
fn refusal(owner: Option<u32>, user: u32) -> String {
    match owner {
        Some(owner) => format!(
            "closed a connection from the user with uid {owner}: this dashboard serves only you (uid {user})"
        ),
        None => format!(
            "closed a connection whose user cannot be told: this dashboard serves only you (uid {user})"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    use super::*;

    const ME: u32 = 1001;

    /// A stand-in for the namespace holder's way in, which answers each
    /// connection with the port it named, then what it was sent.
    fn way_in() -> (WayIn, tempfile::TempDir) {
        let folder = tempfile::tempdir().unwrap();
        let socket = folder.path().join("inward.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                thread::spawn(move || {
                    let mut named = [0; 2];
                    stream.read_exact(&mut named).unwrap();
                    let mut asked = [0; 3];
                    stream.read_exact(&mut asked).unwrap();
                    let port = u16::from_be_bytes(named);
                    let answer = format!("{port} {}", String::from_utf8_lossy(&asked));
                    stream.write_all(answer.as_bytes()).unwrap();
                });
            }
        });
        (WayIn::new(&socket), folder)
    }

    /// A listener on a free port, whose owner check answers `owner`.
    fn listening(owner: Owner) -> (Listening, u16, tempfile::TempDir) {
        let (way_in, folder) = way_in();
        let port = {
            let free = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
            free.local_addr().unwrap().port()
        };
        let listening = open(port, ME, owner, way_in, 37000).unwrap();
        (listening, port, folder)
    }

    /// What a client sending `GET` to `port` gets before the connection
    /// closes, or within five seconds.
    fn fetched(port: u16) -> Vec<u8> {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = client.write_all(b"GET");
        let mut got = Vec::new();
        let mut chunk = [0; 64];
        while let Ok(n @ 1..) = client.read(&mut chunk) {
            got.extend_from_slice(&chunk[..n]);
            if got.len() >= 9 {
                break;
            }
        }
        got
    }

    #[test]
    fn the_user_running_it_reaches_the_dashboards_port() {
        let (_listening, port, _folder) = listening(|_, _| Some(ME));
        assert_eq!(fetched(port), b"37000 GET");
    }

    #[test]
    fn another_users_connection_is_closed_with_nothing_passed_on() {
        // Root, another user, and one that cannot be told.
        let owners: [Owner; 3] = [|_, _| Some(0), |_, _| Some(1002), |_, _| None];
        for (i, owner) in owners.into_iter().enumerate() {
            let (_listening, port, _folder) = listening(owner);
            assert_eq!(fetched(port), b"", "owner {i}");
        }
    }

    /// Asked with the client's address and the listener's own.
    #[test]
    fn the_owner_is_asked_of_the_client_and_the_listeners_address() {
        static ASKED: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>> =
            std::sync::Mutex::new(Vec::new());
        let (_listening, port, _folder) = listening(|client, server| {
            ASKED.lock().unwrap().push((client, server));
            Some(ME)
        });
        let client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let mine = client.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while ASKED.lock().unwrap().is_empty() && Instant::now() < deadline {
            thread::sleep(POLL);
        }
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        assert_eq!(ASKED.lock().unwrap().as_slice(), [(mine, server)]);
    }

    #[test]
    fn dropped_it_stops_listening() {
        let (listening, port, _folder) = listening(|_, _| Some(ME));
        drop(listening);
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }

    #[test]
    fn a_refusal_names_the_owner_and_the_user_it_serves() {
        assert_eq!(
            refusal(Some(1002), ME),
            "closed a connection from the user with uid 1002: this dashboard serves only you (uid 1001)"
        );
        assert!(refusal(None, ME).contains("cannot be told"));
    }
}
