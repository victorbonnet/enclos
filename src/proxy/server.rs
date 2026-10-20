//! Serving connections: one thread per client connection, two while a
//! tunnel relays bytes, and one for each name lookup. Every connection the
//! proxy decides on gets one network log record, written at the decision.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::Proxy;
use super::decide::{Destination, allowed, validated};
use super::request::{Request, origin_head, parse, read_head};
use crate::model::net::{NetEvent, Reason, Verdict, destination};
use crate::model::now;

/// How long a client has to send its whole request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait before accepting again after accepting failed, such as
/// when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The answer to a connection over the proxy's limit.
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 56\r\nConnection: close\r\n\r\nenclos: too many connections at once from this sandbox.\n";

impl Proxy {
    /// Serves the listener until the process ends.
    pub fn serve(self: &Arc<Self>, listener: TcpListener) -> io::Result<thread::JoinHandle<()>> {
        let proxy = Arc::clone(self);
        thread::Builder::new()
            .name("enclos-proxy-accept".into())
            .spawn(move || {
                let open = Arc::new(AtomicUsize::new(0));
                for client in listener.incoming() {
                    let Ok(mut client) = client else {
                        thread::sleep(ACCEPT_BACKOFF);
                        continue;
                    };
                    let Some(slot) = Slot::take(&open, proxy.max_connections) else {
                        let _ = client.write_all(BUSY);
                        continue;
                    };
                    let proxy = Arc::clone(&proxy);
                    let started = thread::Builder::new().spawn(move || {
                        let _slot = slot;
                        proxy.handle(client)
                    });
                    if let Err(e) = started {
                        eprintln!("enclos proxy: cannot start a thread for a connection: {e}");
                    }
                }
            })
    }

    fn handle(&self, mut client: TcpStream) {
        let started = Instant::now();
        let mut event = NetEvent {
            at: now(),
            sandbox: self.sandbox.clone(),
            host: String::new(),
            port: 0,
            method: String::new(),
            address: None,
            verdict: Verdict::Denied,
            reason: Some(Reason::BadRequest),
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
        };
        match self.open(&client, &mut event) {
            Err(reason) => {
                event.reason = Some(reason);
                event.duration_ms = started.elapsed().as_millis() as u64;
                // Logged before the answer, so whoever is refused already finds
                // the refusal in `enclos net denied`.
                self.record(&event);
                let _ = refuse(&mut client, &event, reason);
            }
            Ok((upstream, request, early)) => {
                // Logged as it opens, so a long tunnel shows while it lasts.
                let row = self.record(&event);
                forward(
                    &client,
                    &upstream,
                    request,
                    &early,
                    self.idle_timeout,
                    &mut event,
                );
                event.duration_ms = started.elapsed().as_millis() as u64;
                if let Some(row) = row
                    && let Err(e) = self.log.finish(row, &event)
                {
                    eprintln!(
                        "enclos proxy: could not log the end of a connection to {}: {e}",
                        event.host
                    );
                }
            }
        }
    }

    /// Records `event`; returns its row, unless there was nothing to record.
    fn record(&self, event: &NetEvent) -> Option<i64> {
        // A request that never said where it was going is not worth a row.
        if event.host.is_empty() {
            return None;
        }
        self.log
            .record(event)
            .inspect_err(|e| {
                eprintln!(
                    "enclos proxy: could not log a connection to {}: {e}",
                    event.host
                )
            })
            .ok()
    }

    /// Reads the request and decides on it. When allowed, returns the
    /// upstream connection, the request, and any bytes the client sent after
    /// the head.
    fn open(
        &self,
        client: &TcpStream,
        event: &mut NetEvent,
    ) -> Result<(TcpStream, Request, Vec<u8>), Reason> {
        let mut slow = Until {
            stream: client,
            deadline: Instant::now() + HEAD_TIMEOUT,
        };
        let (head, early) = read_head(&mut slow).map_err(|_| Reason::BadRequest)?;
        let request = parse(&head).ok_or(Reason::BadRequest)?;
        let (host, port) = match &request {
            Request::Connect { host, port } => (host, *port),
            Request::Http { host, port, .. } => (host, *port),
        };
        event.method = match &request {
            Request::Connect { .. } => "CONNECT".to_owned(),
            Request::Http { method, .. } => method.clone(),
        };
        event.port = port;
        let dest = Destination::parse(host, port).inspect_err(|_| {
            // Shown later in a terminal on the host: nothing the client
            // wrote may reach it unescaped.
            event.host = host.escape_default().take(255).collect();
        })?;
        event.host = dest.host.clone();

        let policy = self.policy.policy().map_err(|e| {
            eprintln!("enclos proxy: cannot read the active policy, denying: {e}");
            Reason::NotAllowed
        })?;
        if !allowed(&policy, &dest) {
            return Err(Reason::NotAllowed);
        }
        // From here on the policy allows the destination: a failure to reach
        // it is not a refusal.
        event.verdict = Verdict::Allowed;
        // Resolving and connecting share one deadline.
        let deadline = Instant::now() + self.connect_timeout;
        let resolved = match dest.ip {
            Some(ip) => vec![ip],
            None => self
                .resolve(&dest.host, dest.port, deadline)
                .map_err(|_| Reason::ResolveFailed)?,
        };
        let addrs = validated(&policy, &dest, &resolved, self.classify).inspect_err(|_| {
            event.verdict = Verdict::Denied;
        })?;
        let upstream = self.connect(&addrs, dest.port, deadline, event)?;
        event.reason = None;
        Ok((upstream, request, early))
    }

    /// Resolves the name on a thread of its own and stops waiting at
    /// `deadline`, since the resolver has no deadline of its own. A lookup
    /// given up on keeps its place among the lookups until it returns, so
    /// names that never resolve cannot pile up threads: past
    /// `max_connections` lookups at once, the next one fails at once.
    fn resolve(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Vec<IpAddr>> {
        let lookup = Slot::take(&self.lookups, self.max_connections)
            .ok_or_else(|| io::Error::other("too many lookups still running"))?;
        let (tx, rx) = mpsc::channel();
        let resolver = Arc::clone(&self.resolver);
        let host = host.to_owned();
        thread::Builder::new()
            .name("enclos-proxy-resolve".into())
            .spawn(move || {
                let _lookup = lookup;
                let _ = tx.send(resolver.resolve(&host, port));
            })?;
        let left = deadline.saturating_duration_since(Instant::now());
        rx.recv_timeout(left)
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
    }

    /// Connects to the first validated address that answers, by address, so
    /// nothing resolves the name again behind the check (ADR 0017). The two
    /// address families take turns and all tries share what is left until
    /// `deadline`, so dead addresses of one family cannot hold up a working
    /// one for long.
    fn connect(
        &self,
        addrs: &[IpAddr],
        port: u16,
        deadline: Instant,
        event: &mut NetEvent,
    ) -> Result<TcpStream, Reason> {
        let order = interleaved(addrs);
        for (i, ip) in order.iter().enumerate() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            // What is left, shared among the addresses not tried yet.
            let budget = left / (order.len() - i) as u32;
            let addr = SocketAddr::new(*ip, port);
            if let Ok(stream) = TcpStream::connect_timeout(&addr, budget) {
                event.address = Some(ip.to_string());
                return Ok(stream);
            }
        }
        Err(Reason::ConnectFailed)
    }
}

/// A place among the connections, or the lookups, the proxy runs at once;
/// it frees when dropped, as the connection or lookup ends.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(open: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        open.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()?;
        Some(Slot(Arc::clone(open)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Reads from a client until a deadline, however slowly it sends.
pub(super) struct Until<'a> {
    pub(super) stream: &'a TcpStream,
    pub(super) deadline: Instant,
}

impl Read for Until<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut stream = self.stream;
        stream.read(buf)
    }
}

/// The addresses with the two families taking turns, each in the order
/// given, starting with the family of the first.
pub(super) fn interleaved(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let first_v6 = addrs.first().is_some_and(IpAddr::is_ipv6);
    let (first, second): (Vec<IpAddr>, Vec<IpAddr>) =
        addrs.iter().partition(|ip| ip.is_ipv6() == first_v6);
    let (mut first, mut second) = (first.into_iter(), second.into_iter());
    let mut order = Vec::with_capacity(addrs.len());
    loop {
        match (first.next(), second.next()) {
            (None, None) => return order,
            (a, b) => order.extend(a.into_iter().chain(b)),
        }
    }
}

/// Sends upstream what the client asked for, then relays both ways until
/// the connection ends, or until no byte moved either way for `idle`. Adds
/// the bytes moved to `event`, and the reason `idle` when it was closed for
/// that.
fn forward(
    client: &TcpStream,
    upstream: &TcpStream,
    request: Request,
    early: &[u8],
    idle: Duration,
    event: &mut NetEvent,
) {
    // A peer that stops reading holds up a write no longer than it may stay
    // quiet.
    for stream in [client, upstream] {
        if stream.set_write_timeout(Some(idle)).is_err() {
            return;
        }
    }
    let mut first = match request {
        Request::Connect { .. } => {
            let mut client = client;
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
            {
                return;
            }
            Vec::new()
        }
        Request::Http {
            method,
            path,
            version,
            headers,
            ..
        } => origin_head(&method, &path, &version, &headers, &event.host, event.port).into_bytes(),
    };
    first.extend_from_slice(early);
    let mut writer = upstream;
    if writer.write_all(&first).is_err() {
        return;
    }
    event.bytes_up += first.len() as u64;
    let relayed = relay(client, upstream, idle);
    event.bytes_up += relayed.up;
    event.bytes_down += relayed.down;
    if relayed.idle {
        event.reason = Some(Reason::Idle);
    }
}

/// What a relay moved, and whether it ended because nothing moved for the
/// idle limit.
struct Relayed {
    up: u64,
    down: u64,
    idle: bool,
}

/// When bytes last moved through a connection, either way, as both copies
/// of a relay see it.
struct Activity {
    start: Instant,
    /// Milliseconds from `start` to the last move.
    last: AtomicU64,
}

impl Activity {
    fn new() -> Activity {
        Activity {
            start: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn moved(&self) {
        let at = self.start.elapsed().as_millis() as u64;
        self.last.fetch_max(at, Ordering::Relaxed);
    }

    /// How long nothing has moved.
    fn quiet(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }
}

/// Copies bytes both ways. When the client is done, the server is told so
/// and may still answer; when the server is done, the connection ends; when
/// nothing moved either way for `idle`, both sides are closed.
fn relay(client: &TcpStream, upstream: &TcpStream, idle: Duration) -> Relayed {
    let activity = Activity::new();
    thread::scope(|s| {
        let up = thread::Builder::new().spawn_scoped(s, || {
            let (n, quiet) = copy(client, upstream, &activity, idle);
            let _ = upstream.shutdown(if quiet {
                Shutdown::Both
            } else {
                Shutdown::Write
            });
            (n, quiet)
        });
        let (down, quiet_down) = match up {
            Ok(_) => copy(upstream, client, &activity, idle),
            Err(_) => (0, false),
        };
        // Ends the client side too, which also ends the copy reading it.
        let _ = client.shutdown(Shutdown::Both);
        let (up, quiet_up) = up.map_or((0, false), |up| up.join().unwrap_or((0, false)));
        Relayed {
            up,
            down,
            idle: quiet_up || quiet_down,
        }
    })
}

/// Copies until the reader ends, either side fails, or nothing moved either
/// way for `idle`. Returns the bytes it moved, also when an error, such as
/// a reset, ended it, and whether it stopped for being idle.
fn copy(
    mut from: &TcpStream,
    mut to: &TcpStream,
    activity: &Activity,
    idle: Duration,
) -> (u64, bool) {
    let mut buf = [0u8; 16 * 1024];
    let mut moved = 0;
    loop {
        let quiet = activity.quiet();
        if quiet >= idle {
            return (moved, true);
        }
        // Wakes when the connection would turn idle, unless the other copy
        // moved bytes in the meantime.
        if from.set_read_timeout(Some(idle - quiet)).is_err() {
            return (moved, false);
        }
        match from.read(&mut buf) {
            Ok(0) => return (moved, false),
            Ok(n) => {
                activity.moved();
                if let Err(e) = to.write_all(&buf[..n]) {
                    // A peer that stopped reading for the idle limit.
                    return (moved, timed_out(&e) && activity.quiet() >= idle);
                }
                activity.moved();
                moved += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if timed_out(&e) => {}
            Err(_) => return (moved, false),
        }
    }
}

/// Whether a read or write failed only because its timeout passed.
fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn refuse(client: &mut TcpStream, event: &NetEvent, reason: Reason) -> io::Result<()> {
    let dest = destination(&event.host, event.port);
    let (status, body) = match (event.verdict, reason) {
        (Verdict::Allowed, _) => (
            "502 Bad Gateway",
            format!("enclos: could not reach {dest} ({reason}).\n"),
        ),
        (_, Reason::BadRequest) => (
            "400 Bad Request",
            "enclos: the proxy cannot serve this request: send CONNECT host:port, or a plain-HTTP request with an absolute URL.\n".to_owned(),
        ),
        _ => (
            "403 Forbidden",
            format!(
                "enclos: this sandbox's policy does not allow {dest} ({reason}). Allow it from the host with `enclos policy allow`.\n"
            ),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes())
}
