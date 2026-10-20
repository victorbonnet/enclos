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

/// Resolves nothing.
struct NoResolver;

impl Resolve for NoResolver {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        Err(io::Error::other("no such name"))
    }
}

impl NetLogStore for MemoryLog {
    fn record(&self, event: &NetEvent) -> StateResult<i64> {
        let mut events = self.0.lock().unwrap();
        events.push(event.clone());
        Ok(events.len() as i64 - 1)
    }
    fn finish(&self, row: i64, event: &NetEvent) -> StateResult<()> {
        self.0.lock().unwrap()[row as usize] = event.clone();
        Ok(())
    }
    fn events(&self, _: &SandboxName, _: Option<Timestamp>) -> StateResult<Vec<NetEvent>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn denied(&self, _: &SandboxName) -> StateResult<Vec<DeniedDestination>> {
        Ok(Vec::new())
    }
}

impl MemoryLog {
    /// Waits for `n` records.
    fn wait_for(&self, n: usize) -> Vec<NetEvent> {
        self.wait_until(|events| events.len() >= n)
    }

    /// Waits until the records are `done`, for at most five seconds.
    fn wait_until(&self, done: impl Fn(&[NetEvent]) -> bool) -> Vec<NetEvent> {
        let start = Instant::now();
        loop {
            let events = self.0.lock().unwrap().clone();
            if done(&events) || start.elapsed() > Duration::from_secs(5) {
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
    start_with(allow, Box::new(FakeResolver(resolve_to)), check, |_| {})
}

fn start_with(
    allow: &[String],
    resolver: Box<dyn Resolve>,
    check: fn(IpAddr) -> AddrClass,
    tweak: impl FnOnce(&mut Proxy),
) -> Running {
    let mut p = Policy::default();
    p.net.allow = allow.to_vec();
    let policy = Arc::new(Mutex::new(p));
    let log = MemoryLog::default();
    let mut proxy = Proxy::new(
        "home".parse().unwrap(),
        Box::new(FixedPolicy(Arc::clone(&policy))),
        Box::new(log.clone()),
    )
    .for_tests(resolver, check);
    tweak(&mut proxy);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    Arc::new(proxy).serve(listener).unwrap();
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
    // Logged while it is still open.
    let open = proxy.log.wait_for(1);
    assert_eq!((open[0].verdict, open[0].bytes_down), (Verdict::Allowed, 0));

    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "pong");
    drop(conn);

    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].bytes_down > 0);
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(
        (e.verdict, e.reason, e.method.as_str()),
        (Verdict::Allowed, None, "CONNECT")
    );
    assert_eq!((e.host.as_str(), e.port), ("allowed.example.com", port));
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

#[test]
fn a_host_that_is_not_a_name_is_logged_escaped() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(
        proxy.addr,
        "CONNECT evil\x1b[2J\nnot-allowed.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(!reply.contains('\x1b'), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(events[0].reason, Some(Reason::BadRequest));
    assert_eq!(events[0].host, "evil\\u{1b}[2J\\nnot-allowed.example.com");
}

#[test]
fn an_allowed_name_that_does_not_resolve_failed_and_was_not_refused() {
    let proxy = start_with(
        &["gone.example.com".to_owned()],
        Box::new(NoResolver),
        loopback_is_global,
        |_| {},
    );
    let (_conn, reply) = send(proxy.addr, "CONNECT gone.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(!reply.contains("policy allow"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::ResolveFailed))
    );
}

#[test]
fn connections_over_the_limit_are_turned_away() {
    let proxy = start_with(
        &[],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.max_connections = 1,
    );
    // Holds the one place: it sends nothing yet.
    let first = TcpStream::connect(proxy.addr).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let (_conn, reply) = send(proxy.addr, "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    // Once it is gone, the place is free again.
    drop(first);
    let reply = (0..50)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(20));
            send(proxy.addr, "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n").1
        })
        .find(|reply| !reply.starts_with("HTTP/1.1 503"))
        .unwrap();
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

#[test]
fn a_head_sent_slowly_still_has_one_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    std::thread::spawn(move || {
        // A byte every 50 ms, each well within any one read's timeout.
        for _ in 0..40 {
            if client.write_all(b"G").is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let started = Instant::now();
    let mut slow = server::Until {
        stream: &server,
        deadline: Instant::now() + Duration::from_millis(300),
    };
    assert!(request::read_head(&mut slow).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn address_families_take_turns() {
    let v6 = |n: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n));
    let v4 = |n: u8| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));
    assert_eq!(
        server::interleaved(&[v6(1), v6(2), v6(3), v4(1)]),
        [v6(1), v4(1), v6(2), v6(3)]
    );
    assert_eq!(server::interleaved(&[v4(1), v4(2)]), [v4(1), v4(2)]);
}

/// Answers nothing until long after any test's deadline, as a resolver
/// waiting on a server that never replies does.
struct HangingResolver;

impl Resolve for HangingResolver {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        std::thread::sleep(Duration::from_secs(60));
        Err(io::Error::other("too late"))
    }
}

/// A local server that sends back what it is sent, until the other end
/// closes.
fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut &conn, &mut &conn);
            });
        }
    });
    port
}

/// A local server that streams `n` bytes to each connection, one every
/// `every`, then closes: model output arriving slowly.
fn ticker(n: usize, every: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                for _ in 0..n {
                    std::thread::sleep(every);
                    if conn.write_all(b".").is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// Sends `request` until the proxy serves it rather than turning it away,
/// as the place a closed connection held frees just after its record.
fn send_once_free(addr: std::net::SocketAddr, request: &str) -> String {
    (0..50)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(20));
            send(addr, request).1
        })
        .find(|reply| !reply.starts_with("HTTP/1.1 503"))
        .unwrap()
}

#[test]
fn an_idle_tunnel_is_closed_and_frees_its_place() {
    let port = echo();
    let proxy = start_with(
        &[format!("quiet.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| {
            p.max_connections = 1;
            p.idle_timeout = Duration::from_millis(200);
        },
    );
    let (mut conn, reply) = send(
        proxy.addr,
        &format!("CONNECT quiet.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    conn.write_all(b"hi").unwrap();
    // Neither side sends again: the proxy ends the tunnel, well before the
    // five-second read timeout `send` set.
    let started = Instant::now();
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"hi");
    assert!(started.elapsed() < Duration::from_secs(2));

    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].reason.is_some());
    let e = &events[0];
    assert_eq!(
        (e.verdict, e.reason, e.bytes_up, e.bytes_down),
        (Verdict::Allowed, Some(Reason::Idle), 2, 2)
    );
    // Its place is free again.
    let reply = send_once_free(proxy.addr, "CONNECT other.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

#[test]
fn a_tunnel_that_keeps_moving_bytes_one_way_stays_open() {
    // Ten bytes, one every 100 ms: a second in all, five idle limits.
    let port = ticker(10, Duration::from_millis(100));
    let proxy = start_with(
        &[format!("stream.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.idle_timeout = Duration::from_millis(200),
    );
    let (mut conn, reply) = send(
        proxy.addr,
        &format!("CONNECT stream.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    // The client sends nothing: bytes coming down are enough.
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"..........");
    drop(conn);
    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].bytes_down > 0);
    assert_eq!(
        (events[0].reason, events[0].bytes_down),
        (None, 10),
        "{events:?}"
    );
}

#[test]
fn plain_http_waiting_on_a_silent_server_is_closed_when_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accepts and reads, never answers.
    std::thread::spawn(move || {
        let held: Vec<TcpStream> = listener.incoming().flatten().collect();
        drop(held);
    });
    let proxy = start_with(
        &[format!("silent.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.idle_timeout = Duration::from_millis(200),
    );
    let started = Instant::now();
    let (_conn, reply) = send(
        proxy.addr,
        &format!(
            "GET http://silent.example.com:{port}/ HTTP/1.1\r\nHost: silent.example.com\r\n\r\n"
        ),
    );
    assert_eq!(reply, "");
    assert!(started.elapsed() < Duration::from_secs(2));
    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].reason.is_some());
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::Idle))
    );
}

#[test]
fn a_resolver_that_hangs_is_cut_at_the_deadline() {
    let proxy = start_with(
        &["slow.example.com".to_owned()],
        Box::new(HangingResolver),
        loopback_is_global,
        |p| p.connect_timeout = Duration::from_millis(200),
    );
    let started = Instant::now();
    let (_conn, reply) = send(proxy.addr, "CONNECT slow.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::ResolveFailed))
    );
}

#[test]
fn lookups_given_up_on_count_against_the_limit_until_they_return() {
    let proxy = start_with(
        &["slow.example.com".to_owned()],
        Box::new(HangingResolver),
        loopback_is_global,
        |p| {
            p.max_connections = 1;
            p.connect_timeout = Duration::from_millis(300);
        },
    );
    let request = "CONNECT slow.example.com:443 HTTP/1.1\r\n\r\n";
    assert!(send(proxy.addr, request).1.starts_with("HTTP/1.1 502"));
    // The first lookup still runs and holds the one place for lookups: the
    // next one fails at once rather than start another thread.
    let started = Instant::now();
    let reply = send_once_free(proxy.addr, request);
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(started.elapsed() < Duration::from_millis(250));
    let events = proxy.log.wait_for(2);
    assert_eq!(events[1].reason, Some(Reason::ResolveFailed));
}
