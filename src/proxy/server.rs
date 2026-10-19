//! Serving connections: one thread per client connection, two while a
//! tunnel relays bytes. Every connection ends with one network log record.

use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::Proxy;
use super::decide::{Destination, allowed, validated};
use super::request::{Request, origin_head, parse, read_head};
use crate::model::net::{NetEvent, Reason, Verdict};
use crate::model::now;

/// How long a client has to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

impl Proxy {
    /// Serves the listener until the process ends.
    pub fn serve(self: &Arc<Self>, listener: TcpListener) -> thread::JoinHandle<()> {
        let proxy = Arc::clone(self);
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let proxy = Arc::clone(&proxy);
                thread::spawn(move || proxy.handle(client));
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
        let outcome = self.serve_one(&mut client, &mut event);
        event.duration_ms = started.elapsed().as_millis() as u64;
        if let Err(reason) = outcome {
            event.reason = Some(reason);
            if reason != Reason::ConnectFailed {
                event.verdict = Verdict::Denied;
            }
            // Logged before the answer, so whoever is refused already finds
            // the refusal in `enclos net denied`.
            self.record(&event);
            let _ = refuse(&mut client, &event, reason);
            return;
        }
        self.record(&event);
    }

    fn record(&self, event: &NetEvent) {
        // A request that never said where it was going is not worth a row.
        if !event.host.is_empty()
            && let Err(e) = self.log.record(event)
        {
            eprintln!(
                "enclos proxy: could not log a connection to {}: {e}",
                event.host
            );
        }
    }

    fn serve_one(&self, client: &mut TcpStream, event: &mut NetEvent) -> Result<(), Reason> {
        client
            .set_read_timeout(Some(HEAD_TIMEOUT))
            .map_err(|_| Reason::BadRequest)?;
        let (head, early) = read_head(client).map_err(|_| Reason::BadRequest)?;
        let request = parse(&head).ok_or(Reason::BadRequest)?;
        let (host, port) = match &request {
            Request::Connect { host, port } => (host, *port),
            Request::Http { host, port, .. } => (host, *port),
        };
        event.method = match &request {
            Request::Connect { .. } => "CONNECT".to_owned(),
            Request::Http { method, .. } => method.clone(),
        };
        event.host = host.clone();
        event.port = port;
        let dest = Destination::parse(host, port)?;
        event.host = dest.host.clone();

        let policy = self.policy.policy().map_err(|e| {
            eprintln!("enclos proxy: cannot read the active policy, denying: {e}");
            Reason::NotAllowed
        })?;
        if !allowed(&policy, &dest) {
            return Err(Reason::NotAllowed);
        }
        let resolved = match dest.ip {
            Some(ip) => vec![ip],
            None => self
                .resolver
                .resolve(&dest.host, dest.port)
                .map_err(|_| Reason::ResolveFailed)?,
        };
        let addrs = validated(&policy, &dest, &resolved, self.classify)?;
        event.verdict = Verdict::Allowed;
        let mut upstream = self.connect(&addrs, dest.port, event)?;
        event.reason = None;

        match request {
            Request::Connect { .. } => {
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .map_err(|_| Reason::BadRequest)?;
            }
            Request::Http {
                method,
                path,
                version,
                headers,
                ..
            } => {
                let head = origin_head(&method, &path, &version, &headers, &dest.host, dest.port);
                upstream
                    .write_all(head.as_bytes())
                    .map_err(|_| Reason::ConnectFailed)?;
                event.bytes_up += head.len() as u64;
            }
        }
        if !early.is_empty() {
            upstream
                .write_all(&early)
                .map_err(|_| Reason::ConnectFailed)?;
            event.bytes_up += early.len() as u64;
        }
        let (up, down) = relay(client, upstream);
        event.bytes_up += up;
        event.bytes_down += down;
        Ok(())
    }

    /// Connects to the first validated address that answers, by address, so
    /// nothing resolves the name again behind the check (ADR 0017).
    fn connect(
        &self,
        addrs: &[IpAddr],
        port: u16,
        event: &mut NetEvent,
    ) -> Result<TcpStream, Reason> {
        for ip in addrs {
            let addr = SocketAddr::new(*ip, port);
            if let Ok(stream) = TcpStream::connect_timeout(&addr, self.connect_timeout) {
                event.address = Some(ip.to_string());
                return Ok(stream);
            }
        }
        Err(Reason::ConnectFailed)
    }
}

fn refuse(client: &mut TcpStream, event: &NetEvent, reason: Reason) -> io::Result<()> {
    let (status, text) = match reason {
        Reason::ConnectFailed | Reason::ResolveFailed => ("502 Bad Gateway", "could not reach"),
        Reason::BadRequest => ("400 Bad Request", "cannot serve this request for"),
        _ => ("403 Forbidden", "does not allow"),
    };
    let body = format!(
        "enclos: this sandbox's policy {text} {}:{} ({reason}). Allow it from the host with `enclos policy allow`.\n",
        event.host, event.port
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes())
}

/// Copies bytes both ways; returns (up, down). When the client is done, the
/// server is told so and may still answer; when the server is done, the
/// connection ends.
fn relay(client: &TcpStream, upstream: TcpStream) -> (u64, u64) {
    let _ = client.set_read_timeout(None);
    let (Ok(mut client_r), Ok(mut upstream_w)) = (client.try_clone(), upstream.try_clone()) else {
        return (0, 0);
    };
    let up = thread::spawn(move || {
        let n = io::copy(&mut client_r, &mut upstream_w).unwrap_or(0);
        let _ = upstream_w.shutdown(Shutdown::Write);
        n
    });
    let (mut upstream_r, mut client_w) = (upstream, client.try_clone().ok());
    let down = match client_w.as_mut() {
        Some(w) => io::copy(&mut upstream_r, w).unwrap_or(0),
        None => 0,
    };
    if let Some(w) = client_w {
        // Ends the client side too, which also ends the copy reading it.
        let _ = w.shutdown(Shutdown::Both);
    }
    (up.join().unwrap_or(0), down)
}
