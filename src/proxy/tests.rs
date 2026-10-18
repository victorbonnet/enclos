//! The proxy end to end on loopback: a fake resolver points test names at a
//! local server, and a test address check lets loopback through where the
//! real one never would.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::model::Timestamp;
use crate::model::net::{DeniedDestination, NetEvent, Reason, Verdict};
use crate::state::Result as StateResult;

struct FixedPolicy(Arc<Mutex<Policy>>);

impl PolicySource for FixedPolicy {
    fn policy(&self) -> Result<Policy, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Every name resolves to the address it was given.
struct FakeResolver(IpAddr);

impl Resolve for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        Ok(vec![self.0])
    }
}

#[derive(Clone, Default)]
struct MemoryLog(Arc<Mutex<Vec<NetEvent>>>);

impl NetLogStore for MemoryLog {
    fn record(&self, event: &NetEvent) -> StateResult<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
    fn events(
        &self,
        _: &SandboxName,
        _: Option<&str>,
        _: Option<Timestamp>,
    ) -> StateResult<Vec<NetEvent>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn denied(&self, _: &SandboxName) -> StateResult<Vec<DeniedDestination>> {
        Ok(Vec::new())
    }
}

impl MemoryLog {
    /// Waits for `n` records: the proxy logs a connection once it closes.
    fn wait_for(&self, n: usize) -> Vec<NetEvent> {
        let start = Instant::now();
        loop {
            let events = self.0.lock().unwrap().clone();
            if events.len() >= n || start.elapsed() > Duration::from_secs(5) {
                return events;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn loopback_is_global(ip: IpAddr) -> AddrClass {
    if ip.is_loopback() {
        AddrClass::Global
    } else {
        classify(ip)
    }
}

/// A local server that answers each connection with `reply` after reading
/// one chunk, and hands back what it read.
fn upstream(reply: &'static [u8]) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap_or(0);
            let _ = tx.send(buf[..n].to_vec());
            let _ = conn.write_all(reply);
        }
    });
    (port, rx)
}

struct Running {
    addr: std::net::SocketAddr,
    log: MemoryLog,
    policy: Arc<Mutex<Policy>>,
}

fn start(allow: &[String], resolve_to: IpAddr, check: fn(IpAddr) -> AddrClass) -> Running {
    let mut p = Policy::default();
    p.net.allow = allow.to_vec();
    let policy = Arc::new(Mutex::new(p));
    let log = MemoryLog::default();
    let proxy = Proxy::new(
        "home".parse().unwrap(),
        Box::new(FixedPolicy(Arc::clone(&policy))),
        Box::new(log.clone()),
    )
    .for_tests(Box::new(FakeResolver(resolve_to)), check);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    Arc::new(proxy).serve(listener, Some("main".into()));
    Running { addr, log, policy }
}

fn send(addr: std::net::SocketAddr, request: &str) -> (TcpStream, String) {
    let mut conn = TcpStream::connect(addr).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(request.as_bytes()).unwrap();
    // Up to the end of the response head, or until the proxy closes.
    let mut reply = Vec::new();
    let mut buf = [0u8; 1024];
    while !reply.windows(4).any(|w| w == b"\r\n\r\n") {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => reply.extend_from_slice(&buf[..n]),
        }
    }
    (conn, String::from_utf8_lossy(&reply).into_owned())
}

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[test]
fn an_allowed_tunnel_relays_bytes_and_is_logged() {
    let (port, received) = upstream(b"pong");
    let proxy = start(
        &[format!("allowed.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let (mut conn, reply) = send(
        proxy.addr,
        &format!("CONNECT allowed.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    conn.write_all(b"ping").unwrap();
    assert_eq!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"ping"
    );
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "pong");
    drop(conn);

    let events = proxy.log.wait_for(1);
    let e = &events[0];
    assert_eq!(
        (e.verdict, e.reason, e.method.as_str()),
        (Verdict::Allowed, None, "CONNECT")
    );
    assert_eq!(
        (e.host.as_str(), e.port, e.profile.as_deref()),
        ("allowed.example.com", port, Some("main"))
    );
    assert_eq!(e.address.as_deref(), Some("127.0.0.1"));
    assert_eq!((e.bytes_up, e.bytes_down), (4, 4));
}

#[test]
fn an_unlisted_destination_is_denied_at_once_and_logged() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(proxy.addr, "CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("enclos policy allow"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Denied, Some(Reason::NotAllowed))
    );
    assert_eq!(events[0].host, "evil.example.com");
}

#[test]
fn an_allowed_name_resolving_to_a_blocked_address_is_refused_before_connecting() {
    // The real address check: the metadata address is never reachable.
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    let proxy = start(&["rebind.example.com".to_owned()], metadata, classify);
    let (_conn, reply) = send(
        proxy.addr,
        "CONNECT rebind.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(events[0].reason, Some(Reason::BlockedAddress));
    assert_eq!(events[0].address, None);
}

#[test]
fn plain_http_is_forwarded_in_origin_form() {
    let (port, received) = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let proxy = start(
        &[format!("plain.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let (_conn, reply) = send(
        proxy.addr,
        &format!(
            "GET http://plain.example.com:{port}/weather?city=cali HTTP/1.1\r\nHost: plain.example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    let head = String::from_utf8(received.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert!(
        head.starts_with("GET /weather?city=cali HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("proxy-connection"),
        "{head}"
    );
    assert_eq!(proxy.log.wait_for(1)[0].method, "GET");
}

#[test]
fn a_policy_change_applies_to_the_next_connection() {
    let (port, _received) = upstream(b"");
    let proxy = start(&[], LOCAL, loopback_is_global);
    let request = format!("CONNECT late.example.com:{port} HTTP/1.1\r\n\r\n");
    assert!(send(proxy.addr, &request).1.starts_with("HTTP/1.1 403"));
    proxy.policy.lock().unwrap().net.allow = vec![format!("late.example.com:{port}")];
    assert!(send(proxy.addr, &request).1.starts_with("HTTP/1.1 200"));
}

#[test]
fn garbage_gets_a_400_and_no_log_row() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(proxy.addr, "HELLO\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(proxy.log.0.lock().unwrap().is_empty());
}
