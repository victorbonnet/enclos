//! The dashboard's listener (ADR 0040): the host's 127.0.0.1 at a
//! sandbox's reserved port, open to the user running `enclos dashboard`
//! alone. Every user of the host shares loopback, and a runtime's dashboard
//! gives its page, with its session token, to whoever connects, so the
//! owner of each connection's client socket is read from the kernel's
//! tables, and another user's connection, or one whose owner cannot be
//! told, is closed before a byte is read or passed on. Each other one goes
//! through the namespace holder on Linux, or to the inherited private
//! Unix listener on macOS after checking its URL capability. There is no
//! raw TCP upstream on macOS. The owner check has no setting.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    crate::lifecycle::host::tcp_client_owner(client, server)
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
    serve_on(
        listener,
        Door {
            user,
            owner,
            upstream: Upstream::Namespace { way_in, service },
        },
    )
}

/// The local upstream has no TCP listener to bypass this owner check.
pub(super) fn open_local(
    listener: TcpListener,
    user: u32,
    owner: Owner,
    socket: PathBuf,
    prefix: String,
) -> io::Result<Listening> {
    serve_on(
        listener,
        Door {
            user,
            owner,
            upstream: Upstream::Local { socket, prefix },
        },
    )
}

enum Upstream {
    Namespace { way_in: WayIn, service: u16 },
    Local { socket: PathBuf, prefix: String },
}

impl Upstream {
    fn connect(&self) -> io::Result<UnixStream> {
        match self {
            Self::Namespace { way_in, service } => way_in.connect(*service),
            Self::Local { socket, .. } => UnixStream::connect(socket),
        }
    }
}

/// Serves `listener` through `door` until the result is dropped.
fn serve_on(listener: TcpListener, door: Door) -> io::Result<Listening> {
    // Polled, so that closing it needs no connection to wake it.
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("dashboard".to_owned())
        .spawn(move || door.serve(&listener, &stopped))?;
    Ok(Listening {
        stop,
        thread: Some(thread),
    })
}

/// What each connection is checked against and passed to.
struct Door {
    user: u32,
    owner: Owner,
    upstream: Upstream,
}

impl Door {
    fn serve(self, listener: &TcpListener, stop: &AtomicBool) {
        let door = Arc::new(self);
        let open = Arc::new(AtomicUsize::new(0));
        // Each refused owner said once, not for every connection.
        let refused = Arc::new(Mutex::new(BTreeSet::new()));
        while !stop.load(Ordering::Relaxed) {
            let (client, peer) = match listener.accept() {
                Ok(accepted) => accepted,
                // None waiting, or none can be taken now (out of descriptors).
                Err(_) => {
                    thread::sleep(POLL);
                    continue;
                }
            };
            // Over the limit, closed with nothing said: a browser opens it again.
            let Some(slot) = Slot::take(&open, CONNECTIONS) else {
                continue;
            };
            let door = Arc::clone(&door);
            let refused = Arc::clone(&refused);
            let _ = thread::Builder::new().spawn(move || {
                let _slot = slot;
                let owner = client
                    .local_addr()
                    .ok()
                    .and_then(|server| (door.owner)(peer, server));
                if owner != Some(door.user) {
                    // Close unread, before any connection to the runtime.
                    if refused
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(owner)
                    {
                        crate::notes::say(&refusal(owner, door.user));
                    }
                    return;
                }
                door.pass(client);
            });
        }
    }

    /// Carries `client` to the dashboard's port, or closes it when that
    /// cannot be reached.
    fn pass(&self, mut client: TcpStream) {
        // A socket accepted from a polled listener is polled too on macOS.
        if client.set_nonblocking(false).is_err() {
            return;
        }
        let first = match &self.upstream {
            Upstream::Local { prefix, .. } => match super::http::authorize(&mut client, prefix) {
                Ok(first) => Some(first),
                Err(error) => {
                    super::http::reject(&mut client, &error);
                    return;
                }
            },
            Upstream::Namespace { .. } => None,
        };
        if let Ok(mut upstream) = self.upstream.connect() {
            if let Some(first) = first
                && super::http::begin(&mut client, &mut upstream, first).is_err()
            {
                return;
            }
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

    #[test]
    #[cfg(target_os = "macos")]
    fn on_a_runner_a_second_user_is_refused_even_with_the_url_capability() {
        if std::env::var_os("ENCLOS_HOST_SERVICE_PROBES").is_none() {
            return;
        }
        use std::process::{Command, Stdio};
        fn as_other(args: &[&str]) -> std::process::Output {
            let mut command = Command::new("/usr/bin/sudo");
            command
                .args(["-n", "-u", "nobody"])
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            crate::lifecycle::marker::spawn_unmarked(&mut command)
                .unwrap()
                .wait_with_output()
                .unwrap()
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d");
        let upstream = UnixListener::bind(&socket).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let user = rustix::process::getuid().as_raw();
        let _serving = open_local(
            listener,
            user,
            owner_on_host,
            socket.clone(),
            "/known-capability/".into(),
        )
        .unwrap();
        let url = format!("http://127.0.0.1:{port}/known-capability/");
        let refused = as_other(&["/usr/bin/curl", "-fsS", "--max-time", "3", &url]);
        assert!(!refused.status.success() && refused.stdout.is_empty());
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let denied = as_other(&[
            "/usr/bin/python3",
            "-I",
            "-c",
            "import socket, sys\ns=socket.socket(socket.AF_UNIX)\ntry: s.connect(sys.argv[1])\nexcept PermissionError: sys.exit(0)\nsys.exit(1)",
            socket.to_str().unwrap(),
        ]);
        assert!(
            denied.status.success(),
            "{}",
            String::from_utf8_lossy(&denied.stderr)
        );
        // Control: this user can connect to another loopback server.
        let control = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = control.local_addr().unwrap().port();
        let served = thread::spawn(move || {
            let (mut client, _) = control.accept().unwrap();
            let _ = client.read(&mut [0; 1024]);
            client
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol",
                )
                .unwrap();
        });
        let url = format!("http://127.0.0.1:{port}/");
        let allowed = as_other(&["/usr/bin/curl", "-fsS", "--max-time", "3", &url]);
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert_eq!(allowed.stdout, b"control");
        served.join().unwrap();
    }

    #[test]
    fn the_local_upstream_is_unreachable_without_both_owner_and_url_capability() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d");
        let upstream = UnixListener::bind(&socket).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let _serving = open_local(
            listener,
            ME,
            |_, _| Some(ME),
            socket.clone(),
            "/capability/".into(),
        )
        .unwrap();
        for path in ["/", "/wrong/api/auth/me"] {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            write!(client, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut answer = String::new();
            client.read_to_string(&mut answer).unwrap();
            assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        upstream.set_nonblocking(false).unwrap();
        let serving = thread::spawn(move || {
            let (mut client, _) = upstream.accept().unwrap();
            let mut bytes = [0; 1024];
            let n = client.read(&mut bytes).unwrap();
            let header = String::from_utf8_lossy(&bytes[..n]);
            assert!(header.starts_with("GET /api/auth/me HTTP/1.1\r\n"));
            assert!(header.contains("X-Forwarded-Prefix: /capability\r\n"));
            client
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ntoken")
                .unwrap();
        });
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"GET /capability/api/auth/me HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).unwrap();
        assert!(answer.ends_with("token"));
        serving.join().unwrap();

        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let _other = open_local(listener, ME, |_, _| None, socket, "/capability/".into()).unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = client.write_all(b"GET /capability/ HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(matches!(client.read(&mut [0; 32]), Ok(0) | Err(_)));
    }

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

    /// A listener on a port the system chose, whose owner check answers
    /// `owner`.
    fn listening(owner: Owner) -> (Listening, u16, tempfile::TempDir) {
        let (way_in, folder) = way_in();
        let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let port = listener.local_addr().unwrap().port();
        let door = Door {
            user: ME,
            owner,
            upstream: Upstream::Namespace {
                way_in,
                service: 37000,
            },
        };
        (serve_on(listener, door).unwrap(), port, folder)
    }

    /// What a client sending `GET` to `port` gets before the connection
    /// closes, or within five seconds: nothing when it cannot connect.
    fn fetched(port: u16) -> Vec<u8> {
        let Ok(mut client) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else {
            return Vec::new();
        };
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
    fn one_slow_owner_lookup_does_not_hold_up_other_connections() {
        static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicBool = AtomicBool::new(false);
        let (_listening, port, _folder) = listening(|_, _| {
            LOOKUPS.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(3);
            while !RELEASE.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(POLL);
            }
            Some(ME)
        });
        let mut first = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut second = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        for client in [&mut first, &mut second] {
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(b"GET").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while LOOKUPS.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::sleep(POLL);
        }
        let count = LOOKUPS.load(Ordering::SeqCst);
        RELEASE.store(true, Ordering::SeqCst);
        assert_eq!(count, 2, "owner lookups were serialized");
        for client in [&mut first, &mut second] {
            let mut answer = [0; 9];
            client.read_exact(&mut answer).unwrap();
            assert_eq!(&answer, b"37000 GET");
        }
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

    /// Another test may take the port once it is free, so what is checked
    /// is that this listener no longer serves it.
    #[test]
    fn dropped_it_stops_listening() {
        let (listening, port, _folder) = listening(|_, _| Some(ME));
        assert_eq!(fetched(port), b"37000 GET");
        drop(listening);
        assert_ne!(fetched(port), b"37000 GET");
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
