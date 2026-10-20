//! Serving connections: one thread per client connection, two while a
//! tunnel relays bytes. Every connection the proxy decides on gets one
//! network log record, written at the decision.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
                forward(&client, &upstream, request, &early, &mut event);
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
        let resolved = match dest.ip {
            Some(ip) => vec![ip],
            None => self
                .resolver
                .resolve(&dest.host, dest.port)
                .map_err(|_| Reason::ResolveFailed)?,
        };
        let addrs = validated(&policy, &dest, &resolved, self.classify).inspect_err(|_| {
            event.verdict = Verdict::Denied;
        })?;
        let upstream = self.connect(&addrs, dest.port, event)?;
        event.reason = None;
        Ok((upstream, request, early))
    }

    /// Connects to the first validated address that answers, by address, so
    /// nothing resolves the name again behind the check (ADR 0017). The two
    /// address families take turns and all tries share `connect_timeout`, so
    /// dead addresses of one family cannot hold up a working one for long.
    fn connect(
        &self,
        addrs: &[IpAddr],
        port: u16,
        event: &mut NetEvent,
    ) -> Result<TcpStream, Reason> {
        let deadline = Instant::now() + self.connect_timeout;
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

/// One of the connections the proxy serves at once; the place frees when
/// the connection ends.
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
/// the connection ends. Adds the bytes moved to `event`.
fn forward(
    client: &TcpStream,
    upstream: &TcpStream,
    request: Request,
    early: &[u8],
    event: &mut NetEvent,
) {
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
    let (up, down) = relay(client, upstream);
    event.bytes_up += up;
    event.bytes_down += down;
}

/// Copies bytes both ways; returns (up, down). When the client is done, the
/// server is told so and may still answer; when the server is done, the
/// connection ends.
fn relay(client: &TcpStream, upstream: &TcpStream) -> (u64, u64) {
    let _ = client.set_read_timeout(None);
    thread::scope(|s| {
        let up = thread::Builder::new().spawn_scoped(s, || {
            let n = copy(client, upstream);
            let _ = upstream.shutdown(Shutdown::Write);
            n
        });
        let down = match up {
            Ok(_) => copy(upstream, client),
            Err(_) => 0,
        };
        // Ends the client side too, which also ends the copy reading it.
        let _ = client.shutdown(Shutdown::Both);
        let up = up.map_or(0, |up| up.join().unwrap_or(0));
        (up, down)
    })
}

/// Copies until the reader ends or either side fails, and returns the bytes
/// it moved, also when an error, such as a reset, ended it.
fn copy(mut from: &TcpStream, mut to: &TcpStream) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut moved = 0;
    loop {
        match from.read(&mut buf) {
            Ok(0) => return moved,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return moved;
                }
                moved += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return moved,
        }
    }
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
