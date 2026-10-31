//! The proxy end to end on loopback: a fake resolver points test names at a
//! local server, and a test address check lets loopback through where the
//! real one never would.

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::stream::Stream;
use super::*;
use crate::model::Timestamp;
use crate::model::net::{DeniedDestination, NameSeen, NetEvent, Reason, Verdict};
use crate::state::Result as StateResult;

struct FixedPolicy(Arc<Mutex<Policy>>);

impl PolicySource for FixedPolicy {
    fn policy(&self) -> Result<Policy, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// A state database the proxy cannot read.
struct UnreadablePolicy;

impl PolicySource for UnreadablePolicy {
    fn policy(&self) -> Result<Policy, String> {
        Err("database is locked".into())
    }
}

/// A log store that cannot write, as with a full disk.
struct FailingLog;

impl NetLogStore for FailingLog {
    fn record(&self, _: &NetEvent) -> StateResult<i64> {
        Err(crate::state::StateError::Locked {
            path: "state.db".into(),
        })
    }
    fn finish(&self, _: i64, _: &NetEvent) -> StateResult<()> {
        unreachable!("a connection without a record has no row to finish")
    }
    fn events(&self, _: &SandboxName, _: Option<Timestamp>) -> StateResult<Vec<NetEvent>> {
        Ok(Vec::new())
    }
    fn denied(&self, _: &SandboxName) -> StateResult<Vec<DeniedDestination>> {
        Ok(Vec::new())
    }
}

/// Every name resolves to the address it was given.
struct FakeResolver(IpAddr);

impl Resolve for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        Ok(vec![self.0])
    }
}

/// How long a test waits for what the proxy does on its own threads: long,
/// since a test that passes waits only as long as it takes, and a CI runner
/// busy with the whole suite can take seconds.
const PATIENCE: Duration = Duration::from_secs(30);

/// The records, and how many were finished.
#[derive(Clone, Default)]
struct MemoryLog(
    Arc<Mutex<Vec<NetEvent>>>,
    Arc<std::sync::atomic::AtomicUsize>,
);

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
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

    /// Waits for `n` records to be finished. The count is read before the
    /// records, so they hold every finish it counted: read after, a finish
    /// landing in between would count a record still as it opened.
    fn wait_finished(&self, n: usize) -> Vec<NetEvent> {
        let start = Instant::now();
        loop {
            let finished = self.1.load(std::sync::atomic::Ordering::SeqCst) >= n;
            let events = self.0.lock().unwrap().clone();
            if finished || start.elapsed() > Duration::from_secs(5) {
                return events;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until the records are `done`, for at most [`PATIENCE`].
    fn wait_until(&self, done: impl Fn(&[NetEvent]) -> bool) -> Vec<NetEvent> {
        let start = Instant::now();
        loop {
            let events = self.0.lock().unwrap().clone();
            if done(&events) || start.elapsed() > PATIENCE {
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

/// Where a proxy serves.
#[derive(Clone)]
enum Address {
    Tcp(std::net::SocketAddr),
    Unix(PathBuf),
}

impl Address {
    fn connect(&self) -> Stream {
        match self {
            Address::Tcp(addr) => Stream::Tcp(TcpStream::connect(addr).unwrap()),
            Address::Unix(path) => Stream::Unix(UnixStream::connect(path).unwrap()),
        }
    }
}

struct Running {
    addr: Address,
    log: MemoryLog,
    policy: Arc<Mutex<Policy>>,
    /// Holds the folder of a Unix socket.
    _folder: Option<tempfile::TempDir>,
}

thread_local! {
    /// Whether this test's proxies serve a Unix socket rather than TCP.
    static ON_UNIX: Cell<bool> = const { Cell::new(false) };
}

/// A test of each given behaviour for each kind of listener: `<name>::tcp`
/// and `<name>::unix` run the function `<name>`, which starts its proxies
/// with [`start`] or [`start_with`].
macro_rules! on_both_listeners {
    ($($name:ident),+ $(,)?) => {
        $(mod $name {
            #[test]
            fn tcp() {
                super::$name();
            }

            #[test]
            fn unix() {
                super::ON_UNIX.set(true);
                super::$name();
            }
        })+
    };
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
    let (proxy, log, policy) = built(allow, resolver, check, tweak);
    let (listener, addr, _folder) = if ON_UNIX.get() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("proxy.sock");
        let listener = listen_unix(&path).unwrap();
        (Listener::from(listener), Address::Unix(path), Some(folder))
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        (Listener::from(listener), Address::Tcp(addr), None)
    };
    let proxy = Arc::new(proxy);
    std::thread::spawn(move || proxy.serve_all(vec![listener]));
    Running {
        addr,
        log,
        policy,
        _folder,
    }
}

/// A proxy that allows nothing, served as `proxy run` serves it: on both
/// loopbacks at one port, which it returns with the proxy.
fn start_on_both_loopbacks(tweak: impl FnOnce(&mut Proxy)) -> (u16, MemoryLog, Arc<Proxy>) {
    let (proxy, log, _) = built(&[], Box::new(NoResolver), classify, tweak);
    // Any port, so no other test can take it between choosing and binding.
    // The port chosen on [::1] can be taken on 127.0.0.1 by another
    // program: then another one is chosen.
    let listeners = (0..20)
        .find_map(|_| match listen(0) {
            Ok(listeners) => Some(listeners),
            Err(e) if e.source.kind() == io::ErrorKind::AddrInUse => None,
            Err(e) => panic!("{e:?}"),
        })
        .expect("a port free on both loopbacks");
    let port = listeners[0].local_addr().unwrap().port();
    assert_eq!(listeners.len(), 2);
    // `[::1]` first, so that once 127.0.0.1 answers, both are held.
    assert!(listeners[0].local_addr().unwrap().is_ipv6());
    assert_eq!(
        listeners[1].local_addr().unwrap(),
        (Ipv4Addr::LOCALHOST, port).into()
    );
    let proxy = Arc::new(proxy);
    let serving = Arc::clone(&proxy);
    std::thread::spawn(move || {
        serving.serve_all(listeners.into_iter().map(Listener::from).collect())
    });
    (port, log, proxy)
}

fn built(
    allow: &[String],
    resolver: Box<dyn Resolve>,
    check: fn(IpAddr) -> AddrClass,
    tweak: impl FnOnce(&mut Proxy),
) -> (Proxy, MemoryLog, Arc<Mutex<Policy>>) {
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
    (proxy, log, policy)
}

fn send(addr: Address, request: &str) -> (Stream, String) {
    let mut conn = addr.connect();
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
fn the_limits_are_sized_from_the_descriptors_the_proxy_was_given() {
    // launchd's limit, which they fill as they did when it was the only one.
    assert_eq!(limits_for(Some(256)), (100, 32));
    // systemd's usual soft limit.
    assert_eq!(limits_for(Some(1024)), (431, 137));
    // Past it, or without any limit, threads are what must stay bounded.
    assert_eq!(limits_for(Some(1 << 20)), limits_for(Some(1024)));
    assert_eq!(limits_for(None), limits_for(Some(1024)));
    // Each fits what is left, whatever the limit.
    for descriptors in 32..=1024 {
        let (connections, lookups) = limits_for(Some(descriptors));
        let used = 2 * connections as u64 + lookups as u64;
        assert!(used + OWN_DESCRIPTORS <= descriptors, "{descriptors}");
    }
    // Too few to share still serves one of each.
    assert_eq!(limits_for(Some(8)), (1, 1));
}

fn an_allowed_tunnel_relays_bytes_and_is_logged() {
    let (port, received) = upstream(b"pong");
    let proxy = start(
        &[format!("allowed.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let (mut conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT allowed.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    conn.write_all(b"ping").unwrap();
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"ping");
    // Logged while it is still open: with the bytes relayed so far, none or
    // the upstream's answer, which may already be on its way.
    let open = proxy.log.wait_for(1);
    assert_eq!(open[0].verdict, Verdict::Allowed);
    assert!(matches!(open[0].bytes_down, 0 | 4), "{:?}", open[0]);

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

fn an_unlisted_destination_is_denied_at_once_and_logged() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(reply.contains("enclos policy allow"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Denied, Some(Reason::NotAllowed))
    );
    assert_eq!(events[0].host, "evil.example.com");
}

fn an_unreadable_policy_denies_with_its_own_reason_and_nothing_to_allow() {
    let proxy = start_with(
        &[],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.policy = Box::new(UnreadablePolicy),
    );
    let mut conn = proxy.addr.connect();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(conn, "CONNECT allowed.example.com:443 HTTP/1.1\r\n\r\n").unwrap();
    let mut reply = String::new();
    let _ = conn.read_to_string(&mut reply);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(!reply.contains("policy allow"), "{reply}");
    assert!(reply.contains("enclos logs home"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Denied, Some(Reason::PolicyUnreadable))
    );
    assert_eq!(events[0].address, None);
}

fn an_allowed_tunnel_is_served_even_when_its_record_cannot_be_written() {
    // Today's behaviour, fail open (design §6). ADR 0027 proposes refusing
    // it instead; accepting it turns this test around.
    let (port, received) = upstream(b"pong");
    let proxy = start_with(
        &[format!("allowed.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.log = Box::new(FailingLog),
    );
    let (mut conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT allowed.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    conn.write_all(b"ping").unwrap();
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"ping");
}

fn an_allowed_name_resolving_to_a_blocked_address_is_refused_before_connecting() {
    // The real address check: the metadata address is never reachable.
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    let proxy = start(&["rebind.example.com".to_owned()], metadata, classify);
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT rebind.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(events[0].reason, Some(Reason::BlockedAddress));
    assert_eq!(events[0].address, None);
}

fn plain_http_is_forwarded_in_origin_form() {
    let (port, received) = upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let proxy = start(
        &[format!("plain.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let (_conn, reply) = send(
        proxy.addr.clone(),
        &format!(
            "GET http://plain.example.com:{port}/weather?city=cali HTTP/1.1\r\nHost: plain.example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    let head = String::from_utf8(received.recv_timeout(PATIENCE).unwrap()).unwrap();
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

/// A local server that reads each connection until the client is done
/// sending, then answers `reply` and hands back all it read.
fn upstream_reading_all(reply: &'static [u8]) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut all = Vec::new();
            let _ = conn.read_to_end(&mut all);
            let _ = tx.send(all);
            let _ = conn.write_all(reply);
        }
    });
    (port, rx)
}

const SECOND: &str = "GET /second HTTP/1.1\r\nHost: other.example.net\r\n\r\n";

/// Sends `writes` to the proxy one after the other, for an allowed host
/// whose server reads until the proxy is done sending; returns what that
/// server read, and what the client read back.
fn plain_http_exchange(writes: &[&str], then_close: bool) -> (String, String) {
    let (port, received) = upstream_reading_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let proxy = start(
        &[format!("plain.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let mut conn = proxy.addr.connect();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for write in writes {
        let write = write.replace("{port}", &port.to_string());
        // Once the proxy is done with the client, a later write may fail.
        let _ = conn.write_all(write.as_bytes());
        std::thread::sleep(Duration::from_millis(100));
    }
    if then_close {
        let _ = conn.shutdown(std::net::Shutdown::Write);
    }
    let all = received.recv_timeout(PATIENCE).unwrap();
    let mut reply = Vec::new();
    let _ = conn.read_to_end(&mut reply);
    (
        String::from_utf8(all).unwrap(),
        String::from_utf8_lossy(&reply).into_owned(),
    )
}

fn a_plain_http_connection_carries_one_request_and_its_body() {
    // The body comes in two writes; the second request after it, in the
    // same write and in a later one, would reach the same address with
    // another `Host`. The client never closes: sending past the body is
    // enough for the server to be told the client is done.
    let head = "POST http://plain.example.com:{port}/form HTTP/1.1\r\nContent-Length: 9\r\n\r\n";
    let (all, reply) = plain_http_exchange(
        &[&format!("{head}name=ca"), &format!("li{SECOND}"), SECOND],
        false,
    );
    assert!(all.starts_with("POST /form HTTP/1.1\r\n"), "{all}");
    assert!(all.ends_with("\r\n\r\nname=cali"), "{all}");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
}

fn a_second_request_sent_with_the_head_is_dropped() {
    let cases = [
        (
            "GET http://plain.example.com:{port}/ HTTP/1.1\r\n\r\n",
            "\r\n\r\n",
        ),
        (
            "POST http://plain.example.com:{port}/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody",
            "\r\n\r\nbody",
        ),
    ];
    for (first, ends) in cases {
        let (all, reply) = plain_http_exchange(&[&format!("{first}{SECOND}")], false);
        assert!(all.ends_with(ends), "{first}: {all}");
        assert!(!all.contains("other.example.net"), "{first}: {all}");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{first}: {reply}");
    }
}

fn a_tunnel_keeps_what_the_client_sent_with_its_connect() {
    let (port, received) = upstream_reading_all(b"");
    let proxy = start(
        &[format!("tunnel.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let mut conn = proxy.addr.connect();
    conn.write_all(
        format!("CONNECT tunnel.example.com:{port} HTTP/1.1\r\n\r\nhello, early").as_bytes(),
    )
    .unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let all = received.recv_timeout(PATIENCE).unwrap();
    assert_eq!(all, b"hello, early");
}

fn a_plain_http_head_a_server_could_split_otherwise_is_refused_and_recorded() {
    let (port, received) = upstream_reading_all(b"");
    let proxy = start(
        &[format!("plain.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let heads = [
        "POST http://plain.example.com:{port}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
        "GET http://plain.example.com:{port}/ HTTP/1.1\r\nX: a\n\nGET /admin HTTP/1.1\nHost: other.example.net\nY: z\r\n\r\n",
    ];
    for (i, head) in heads.iter().enumerate() {
        let head = head.replace("{port}", &port.to_string());
        let (_conn, reply) = send(proxy.addr.clone(), &head);
        assert!(reply.starts_with("HTTP/1.1 400"), "{head}: {reply}");
        assert!(reply.contains("Transfer-Encoding"), "{reply}");
        let events = proxy.log.wait_for(i + 1);
        assert_eq!(events[i].host, "plain.example.com", "{head}");
        assert_eq!(events[i].reason, Some(Reason::BadRequest), "{head}");
    }
    assert!(
        received.recv_timeout(Duration::from_millis(200)).is_err(),
        "the server was reached"
    );
}

fn a_policy_change_applies_to_the_next_connection() {
    let (port, _received) = upstream(b"");
    let proxy = start(&[], LOCAL, loopback_is_global);
    let request = format!("CONNECT late.example.com:{port} HTTP/1.1\r\n\r\n");
    assert!(
        send(proxy.addr.clone(), &request)
            .1
            .starts_with("HTTP/1.1 403")
    );
    proxy.policy.lock().unwrap().net.allow = vec![format!("late.example.com:{port}")];
    assert!(
        send(proxy.addr.clone(), &request)
            .1
            .starts_with("HTTP/1.1 200")
    );
}

fn garbage_gets_a_400_and_no_log_row() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(proxy.addr.clone(), "HELLO\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(proxy.log.0.lock().unwrap().is_empty());
}

fn a_host_that_is_not_a_name_is_logged_escaped() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT evil\x1b[2J\nnot-allowed.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(!reply.contains('\x1b'), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(events[0].reason, Some(Reason::BadRequest));
    assert_eq!(events[0].host, "evil\\u{1b}[2J\\nnot-allowed.example.com");
}

/// The full set of targets is in `loggable_host`'s own test; these check
/// that each way a target reaches the log goes through it.
fn a_bad_target_is_logged_without_its_user_or_query() {
    let cases = [
        ("user:secret@api.example.com:443", "api.example.com"),
        ("[user:secret@::1]:443", "::1"),
        ("api.example.com?token=secret:443", "api.example.com"),
    ];
    for (target, logged) in cases {
        let proxy = start(&[], LOCAL, loopback_is_global);
        let (_conn, reply) = send(
            proxy.addr.clone(),
            &format!("CONNECT {target} HTTP/1.1\r\n\r\n"),
        );
        assert!(reply.starts_with("HTTP/1.1 400"), "{target}: {reply}");
        let events = proxy.log.wait_for(1);
        assert_eq!(events[0].reason, Some(Reason::BadRequest), "{target}");
        assert_eq!(events[0].host, logged, "{target}");
    }
}

fn a_plain_http_target_is_logged_without_its_query_or_fragment() {
    for target in [
        "http://api.example.com?token=secret",
        "http://api.example.com#secret",
    ] {
        let proxy = start(&[], LOCAL, loopback_is_global);
        let (_conn, reply) = send(
            proxy.addr.clone(),
            &format!("GET {target} HTTP/1.1\r\n\r\n"),
        );
        assert!(reply.starts_with("HTTP/1.1 400"), "{target}: {reply}");
        let events = proxy.log.wait_for(1);
        assert_eq!(events[0].reason, Some(Reason::BadRequest), "{target}");
        assert_eq!(events[0].host, "api.example.com", "{target}");
    }
}

fn a_plain_http_target_with_a_user_gets_a_400_and_no_log_row() {
    let proxy = start(&[], LOCAL, loopback_is_global);
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "GET http://user:secret@api.example.com/ HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(proxy.log.0.lock().unwrap().is_empty());
}

fn an_allowed_name_that_does_not_resolve_failed_and_was_not_refused() {
    let proxy = start_with(
        &["gone.example.com".to_owned()],
        Box::new(NoResolver),
        loopback_is_global,
        |_| {},
    );
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT gone.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(!reply.contains("policy allow"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::ResolveFailed))
    );
}

fn connections_over_the_limit_are_turned_away() {
    let proxy = start_with(
        &[],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.max_connections = 1,
    );
    // Holds the one place: it sends nothing yet.
    let first = proxy.addr.connect();
    std::thread::sleep(Duration::from_millis(100));
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    // Once it is gone, the place is free again.
    drop(first);
    let reply = send_once_free(&proxy.addr, "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n");
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

#[test]
fn the_proxy_serves_both_loopbacks_the_same_way() {
    let (port, log, _) = start_on_both_loopbacks(|_| {});
    let request = "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n";
    let (_v4, reply) = send(Address::Tcp((Ipv4Addr::LOCALHOST, port).into()), request);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    let (_v6, reply) = send(Address::Tcp((Ipv6Addr::LOCALHOST, port).into()), request);
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    // One log for both.
    let events = log.wait_for(2);
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.verdict == Verdict::Denied));
}

#[test]
fn both_loopbacks_share_one_connection_limit() {
    let (port, _log, proxy) = start_on_both_loopbacks(|p| p.max_connections = 1);
    // Holds the one place on 127.0.0.1: it sends nothing yet.
    let _first = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while proxy.open.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the first connection was never accepted"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let (_conn, reply) = send(
        Address::Tcp((Ipv6Addr::LOCALHOST, port).into()),
        "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
}

#[test]
fn a_unix_socket_and_the_loopback_share_one_limit_and_one_log() {
    let folder = tempfile::tempdir().unwrap();
    let socket = Address::Unix(folder.path().join("proxy.sock"));
    let Address::Unix(path) = &socket else {
        unreachable!()
    };
    let unix = listen_unix(path).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let loopback = Address::Tcp(tcp.local_addr().unwrap());
    let (proxy, log, _) = built(&[], Box::new(NoResolver), classify, |p| {
        p.max_connections = 1
    });
    let proxy = Arc::new(proxy);
    let serving = Arc::clone(&proxy);
    std::thread::spawn(move || serving.serve_all(vec![unix.into(), tcp.into()]));

    let request = "CONNECT a.example.com:443 HTTP/1.1\r\n\r\n";
    // Holds the one place, on the socket: it sends nothing yet.
    let first = socket.connect();
    let deadline = Instant::now() + PATIENCE;
    while proxy.open.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "never accepted");
        std::thread::sleep(Duration::from_millis(10));
    }
    let (_conn, reply) = send(loopback.clone(), request);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    drop(first);
    assert!(send_once_free(&loopback, request).starts_with("HTTP/1.1 403"));
    assert!(send_once_free(&socket, request).starts_with("HTTP/1.1 403"));
    assert_eq!(log.wait_for(2).len(), 2);
}

#[test]
fn a_socket_left_by_a_dead_proxy_is_taken_over() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("proxy.sock");
    drop(listen_unix(&path).unwrap());
    assert!(path.exists(), "dropping a listener leaves its socket");
    let _taken = listen_unix(&path).unwrap();
    UnixStream::connect(&path).unwrap();
}

#[test]
fn a_socket_a_proxy_answers_on_is_left_to_it() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("proxy.sock");
    let _serving = listen_unix(&path).unwrap();
    let e = listen_unix(&path).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
    UnixStream::connect(&path).unwrap();
}

#[test]
fn a_file_in_a_sockets_place_is_kept() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("proxy.sock");
    std::fs::write(&path, "kept").unwrap();
    let e = listen_unix(&path).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept");
}

#[test]
fn a_port_taken_on_either_loopback_is_listened_on_by_neither() {
    // Taken on `[::1]`: the proxy stops there, before 127.0.0.1.
    let squatter = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
    let port = squatter.local_addr().unwrap().port();
    let e = listen(port).unwrap_err();
    assert_eq!(e.addr, (Ipv6Addr::LOCALHOST, port).into());
    assert_eq!(e.source.kind(), io::ErrorKind::AddrInUse);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    // Taken on 127.0.0.1: the `[::1]` listener it already had is let go.
    let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = squatter.local_addr().unwrap().port();
    let e = listen(port).unwrap_err();
    assert_eq!(e.addr, (Ipv4Addr::LOCALHOST, port).into());
    assert_eq!(e.source.kind(), io::ErrorKind::AddrInUse);
    assert!(TcpListener::bind((Ipv6Addr::LOCALHOST, port)).is_ok());
}

#[test]
fn serving_ends_when_any_accept_thread_ends_even_by_panicking() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let e = super::server::until_one_ends(vec![true, false], |panics| {
            if panics {
                panic!("an accept thread panicked (expected by this test)");
            }
            loop {
                std::thread::park();
            }
        });
        let _ = done.send(e.to_string());
    });
    // Otherwise the other thread would serve its loopback alone, and the
    // dead one's port would be free for another program.
    assert!(
        finished.recv_timeout(PATIENCE).is_ok(),
        "serving went on with one accept thread dead"
    );
}

#[test]
fn a_head_sent_slowly_still_has_one_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = stream::Stream::from(listener.accept().unwrap().0);
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
fn send_once_free(addr: &Address, request: &str) -> String {
    (0..50)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(20));
            send(addr.clone(), request).1
        })
        .find(|reply| !reply.starts_with("HTTP/1.1 503"))
        .unwrap()
}

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
        proxy.addr.clone(),
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
    let reply = send_once_free(
        &proxy.addr,
        "CONNECT other.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

fn a_tunnel_that_keeps_moving_bytes_one_way_stays_open() {
    // Twenty bytes, one every 50 ms: a second in all, over three idle limits.
    let port = ticker(20, Duration::from_millis(50));
    let proxy = start_with(
        &[format!("stream.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.idle_timeout = Duration::from_millis(300),
    );
    let (mut conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT stream.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    // The client sends nothing: bytes coming down are enough.
    let mut answer = Vec::new();
    conn.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"....................");
    drop(conn);
    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].bytes_down > 0);
    assert_eq!(
        (events[0].reason, events[0].bytes_down),
        (None, 20),
        "{events:?}"
    );
}

fn plain_http_waiting_on_a_silent_server_is_closed_when_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accepts and holds each connection, never reads or answers.
    std::thread::spawn(move || {
        let _held: Vec<TcpStream> = listener.incoming().flatten().collect();
    });
    let proxy = start_with(
        &[format!("silent.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| p.idle_timeout = Duration::from_millis(200),
    );
    let started = Instant::now();
    let (mut conn, reply) = send(
        proxy.addr.clone(),
        &format!(
            "GET http://silent.example.com:{port}/ HTTP/1.1\r\nHost: silent.example.com\r\n\r\n"
        ),
    );
    // The client learns why, rather than getting an empty reply.
    assert!(reply.starts_with("HTTP/1.1 504"), "{reply}");
    assert!(started.elapsed() < Duration::from_secs(2));
    let mut rest = String::new();
    conn.read_to_string(&mut rest).unwrap();
    let body = (reply + &rest).split_once("\r\n\r\n").unwrap().1.to_owned();
    assert!(body.starts_with("enclos: "), "{body}");
    assert!(body.contains("(idle)"), "{body}");
    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].reason.is_some());
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::Idle))
    );
}

fn a_resolver_that_hangs_is_cut_at_the_deadline() {
    let proxy = start_with(
        &["slow.example.com".to_owned()],
        Box::new(HangingResolver),
        loopback_is_global,
        |p| p.connect_timeout = Duration::from_millis(200),
    );
    let started = Instant::now();
    let (_conn, reply) = send(
        proxy.addr.clone(),
        "CONNECT slow.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    let events = proxy.log.wait_for(1);
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::ResolveFailed))
    );
}

/// A local server that sends as fast as it can and drops what it is sent,
/// until the other end closes.
fn flood() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let reader = conn.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut &reader, &mut std::io::sink());
            });
            std::thread::spawn(move || {
                let chunk = [b'x'; 16 * 1024];
                while (&conn).write_all(&chunk).is_ok() {}
            });
        }
    });
    port
}

fn a_client_that_stops_reading_is_closed_even_while_it_sends() {
    let port = flood();
    let proxy = start_with(
        &[format!("flood.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| {
            p.max_connections = 1;
            p.idle_timeout = Duration::from_millis(300);
        },
    );
    let (conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT flood.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    // The client keeps sending, a byte every 50 ms, so the connection is
    // never quiet, but it never reads what comes down again.
    let sender = conn.try_clone().unwrap();
    std::thread::spawn(move || {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) && (&sender).write_all(b".").is_ok() {
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let events = proxy
        .log
        .wait_until(|e| e.len() == 1 && e[0].reason.is_some());
    assert_eq!(
        (events[0].verdict, events[0].reason),
        (Verdict::Allowed, Some(Reason::Idle)),
        "{events:?}"
    );
    // Its place is free again, while the client still holds its end.
    let reply = send_once_free(
        &proxy.addr,
        "CONNECT other.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    drop(conn);
}

/// Takes `slow` to answer for `name`, as a resolver waiting on a server
/// that answers late does, and answers at once for any other name.
struct SlowFor {
    name: &'static str,
    slow: Duration,
}

impl Resolve for SlowFor {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
        if host == self.name {
            std::thread::sleep(self.slow);
        }
        Ok(vec![LOCAL])
    }
}

fn lookups_given_up_on_count_against_the_limit_until_they_return() {
    let port = echo();
    let proxy = start_with(
        &[
            "slow.example.com".to_owned(),
            format!("fast.example.com:{port}"),
        ],
        Box::new(SlowFor {
            name: "slow.example.com",
            slow: Duration::from_secs(1),
        }),
        loopback_is_global,
        |p| {
            p.max_lookups = 1;
            p.connect_timeout = Duration::from_millis(200);
        },
    );
    let slow = "CONNECT slow.example.com:443 HTTP/1.1\r\n\r\n";
    assert!(send(proxy.addr.clone(), slow).1.starts_with("HTTP/1.1 502"));
    // The first lookup still runs and holds the one place for lookups: a
    // name that would resolve at once fails rather than start another.
    let fast = format!("CONNECT fast.example.com:{port} HTTP/1.1\r\n\r\n");
    let reply = send(proxy.addr.clone(), &fast).1;
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    let events = proxy.log.wait_for(2);
    assert_eq!(
        (events[1].verdict, events[1].reason),
        (Verdict::Allowed, Some(Reason::ResolveFailed))
    );
    // Once the first lookup returns, its place is free again.
    let started = Instant::now();
    let reply = loop {
        let reply = send(proxy.addr.clone(), &fast).1;
        if reply.starts_with("HTTP/1.1 200") || started.elapsed() > Duration::from_secs(5) {
            break reply;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
}

/// A tunnel opened through the proxy for `host:port`, past its `200`.
fn tunnel(proxy: &Running, host: &str, port: u16) -> Stream {
    let (conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT {host}:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    conn
}

/// The one record, once its tunnel closed.
fn closed(proxy: &Running) -> NetEvent {
    let events = proxy.log.wait_finished(1);
    assert_eq!(events.len(), 1, "{events:?}");
    events[0].clone()
}

/// Reads until the proxy closes `conn`, which must be soon.
fn closed_soon(conn: &mut Stream) -> Vec<u8> {
    let started = Instant::now();
    let mut rest = Vec::new();
    // A proxy that closes while the client still sends resets it: closed too.
    match conn.read_to_end(&mut rest) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("{e}"),
    }
    assert!(started.elapsed() < Duration::from_secs(2), "not closed");
    rest
}

fn api(port: u16) -> Running {
    start(
        &[format!("api.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    )
}

fn a_tunnel_whose_hello_names_its_host_goes_through_with_the_name_logged() {
    let (port, received) = upstream_reading_all(b"pong");
    let proxy = api(port);
    let mut conn = tunnel(&proxy, "api.example.com", port);
    // Another case and a final dot name the same host; sent in two parts,
    // the hello goes up whole, once complete, and what follows after it.
    let hello = hello::client_hello_bytes(Some("API.example.com."), false, 16_384);
    conn.write_all(&hello[..10]).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    conn.write_all(&[&hello[10..], b"extra"].concat()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    conn.write_all(b"more").unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(
        received.recv_timeout(PATIENCE).unwrap(),
        [&hello[..], b"extra", b"more"].concat()
    );
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "pong");
    let e = closed(&proxy);
    assert_eq!((e.verdict, e.reason), (Verdict::Allowed, None));
    assert_eq!(e.name_seen, Some(NameSeen::Name("API.example.com.".into())));
    assert_eq!(e.bytes_up, hello.len() as u64 + 9);
}

fn a_hello_split_between_the_request_and_the_tunnel_goes_up_once() {
    let (port, received) = upstream_reading_all(b"");
    let proxy = api(port);
    let hello = hello::client_hello_bytes(Some("api.example.com"), false, 100);
    let mut conn = proxy.addr.connect();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(
        &[
            format!("CONNECT api.example.com:{port} HTTP/1.1\r\n\r\n").as_bytes(),
            &hello[..300],
        ]
        .concat(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(50));
    conn.write_all(&hello[300..]).unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), hello);
}

fn a_tunnel_whose_hello_names_another_server_is_closed_before_it_reaches_it() {
    // A server that never closes on its own: only the proxy ends this.
    let port = echo();
    let proxy = api(port);
    for (early, record) in [(true, 16_384), (false, 100)] {
        proxy.log.0.lock().unwrap().clear();
        proxy.log.1.store(0, std::sync::atomic::Ordering::SeqCst);
        let hello = hello::client_hello_bytes(Some("evil.example.com"), false, record);
        let mut conn = proxy.addr.connect();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let request = format!("CONNECT api.example.com:{port} HTTP/1.1\r\n\r\n");
        // Sent with the request, as a client in a hurry sends it, or after.
        match early {
            true => conn
                .write_all(&[request.as_bytes(), &hello].concat())
                .unwrap(),
            false => {
                conn.write_all(request.as_bytes()).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                conn.write_all(&hello).unwrap();
            }
        }
        let reply = String::from_utf8_lossy(&closed_soon(&mut conn)).into_owned();
        // The `200` and nothing else: the echo never saw the hello.
        assert_eq!(reply, "HTTP/1.1 200 Connection established\r\n\r\n");
        let e = closed(&proxy);
        assert_eq!(
            (e.verdict, e.reason),
            (Verdict::Denied, Some(Reason::NameMismatch))
        );
        assert_eq!(e.name_seen, Some(NameSeen::Name("evil.example.com".into())));
        assert_eq!((e.bytes_up, e.bytes_down), (0, 0));
    }
}

fn a_server_name_is_logged_escaped_and_cut() {
    let port = echo();
    let proxy = api(port);
    let mut conn = tunnel(&proxy, "api.example.com", port);
    let name = format!("evil\u{1b}[2J\n2026-01-01 allowed {}", "a".repeat(400));
    conn.write_all(&hello::hello_with(
        &[hello::sni(name.as_bytes())],
        10,
        16_384,
    ))
    .unwrap();
    closed_soon(&mut conn);
    let e = closed(&proxy);
    assert_eq!(e.reason, Some(Reason::NameMismatch));
    let Some(NameSeen::Name(shown)) = e.name_seen else {
        panic!("{e:?}")
    };
    assert!(!shown.chars().any(char::is_control), "{shown}");
    assert!(shown.starts_with("evil\\u{1b}[2J\\n"), "{shown}");
    assert_eq!(shown.len(), 255);
}

fn a_tunnel_whose_server_speaks_first_works_and_is_logged_as_not_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Some(mut conn) = listener.incoming().flatten().next() {
            conn.write_all(b"220 banner\r\n").unwrap();
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap_or(0);
            let _ = tx.send(buf[..n].to_vec());
            let _ = conn.write_all(b"250 ok\r\n");
        }
    });
    let proxy = start(
        &[format!("mail.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let (mut conn, reply) = send(
        proxy.addr.clone(),
        &format!("CONNECT mail.example.com:{port} HTTP/1.1\r\n\r\n"),
    );
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    // The server speaks first, so its banner can come in the same read as
    // the reply's head: what follows the head is the banner's start.
    let head = reply.find("\r\n\r\n").unwrap() + 4;
    let mut banner = reply.as_bytes()[head..].to_vec();
    while banner.len() < 12 {
        let mut more = [0u8; 12];
        let n = conn.read(&mut more).unwrap();
        assert!(n > 0, "the tunnel closed before the banner");
        banner.extend_from_slice(&more[..n]);
    }
    assert_eq!(banner, b"220 banner\r\n");
    conn.write_all(b"EHLO x\r\n").unwrap();
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"EHLO x\r\n");
    let mut rest = String::new();
    conn.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "250 ok\r\n");
    drop(conn);
    let e = closed(&proxy);
    assert_eq!((e.verdict, e.reason), (Verdict::Allowed, None));
    assert_eq!(e.name_seen, Some(NameSeen::NotTls));
}

fn a_client_done_before_it_sent_anything_still_gets_the_servers_answer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Some(mut conn) = listener.incoming().flatten().next() {
            std::thread::sleep(Duration::from_millis(100));
            let _ = conn.write_all(b"220 banner\r\n");
        }
    });
    let proxy = start(
        &[format!("mail.example.com:{port}")],
        LOCAL,
        loopback_is_global,
    );
    let mut conn = tunnel(&proxy, "mail.example.com", port);
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "220 banner\r\n");
    let e = closed(&proxy);
    assert_eq!(
        (e.verdict, e.reason, e.name_seen),
        (Verdict::Allowed, None, None)
    );
}

/// For a host name, a hello naming no server, or under ECH another, is
/// closed, and nothing goes up (design §6).
fn a_hello_with_no_name_or_ech_with_another_is_closed() {
    for (name, encrypted, seen, reason) in [
        (None, false, NameSeen::NoName, Reason::NoServerName),
        (
            Some("public.example.net"),
            true,
            NameSeen::Encrypted {
                public: Some("public.example.net".into()),
            },
            Reason::EncryptedHello,
        ),
    ] {
        let (port, received) = upstream(b"pong");
        let proxy = api(port);
        let mut conn = tunnel(&proxy, "api.example.com", port);
        conn.write_all(&hello::client_hello_bytes(name, encrypted, 16_384))
            .unwrap();
        assert!(closed_soon(&mut conn).is_empty());
        assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"");
        let e = closed(&proxy);
        assert_eq!(
            (e.verdict, e.reason, e.name_seen, e.bytes_up),
            (Verdict::Denied, Some(reason), Some(seen), 0)
        );
    }
}

/// Browsers send an ECH extension of no use (GREASE) with the name they ask
/// for: it is compared, and goes through.
fn a_hello_with_ech_and_its_own_name_is_checked_and_goes_through() {
    let (port, received) = upstream(b"pong");
    let proxy = api(port);
    let mut conn = tunnel(&proxy, "api.example.com", port);
    let hello = hello::client_hello_bytes(Some("api.example.com"), true, 16_384);
    conn.write_all(&hello).unwrap();
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), hello);
    drop(conn);
    let e = closed(&proxy);
    assert_eq!((e.verdict, e.reason), (Verdict::Allowed, None));
    assert_eq!(e.name_seen, Some(NameSeen::Name("api.example.com".into())));
}

fn a_tunnel_whose_tls_does_not_read_as_one_hello_is_closed() {
    let good = hello::client_hello_bytes(Some("evil.example.com"), false, 16_384);
    let mut old_version = good.clone();
    old_version[1] = 0;
    for bytes in [
        vec![0x16, 3, 1, 0, 4, 0x02, 0, 0, 0],
        old_version,
        [&[0x15, 3, 1, 0, 2, 1, 0x5a][..], &good].concat(),
        hello::hello_with(
            &[
                hello::sni(b"evil.example.com"),
                hello::sni(b"api.example.com"),
            ],
            10,
            16_384,
        ),
    ] {
        let (port, received) = upstream(b"pong");
        let proxy = api(port);
        let mut conn = tunnel(&proxy, "api.example.com", port);
        conn.write_all(&bytes).unwrap();
        assert!(closed_soon(&mut conn).is_empty());
        assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"");
        let e = closed(&proxy);
        assert_eq!(
            (e.verdict, e.reason, e.name_seen, e.bytes_up),
            (
                Verdict::Denied,
                Some(Reason::HelloUnreadable),
                Some(NameSeen::Unreadable),
                0
            )
        );
    }
}

fn a_hello_that_says_it_is_longer_than_the_cap_is_closed_at_once() {
    let (port, received) = upstream(b"pong");
    let proxy = api(port);
    let mut conn = tunnel(&proxy, "api.example.com", port);
    // A first record of 65,535 bytes holding a handshake of 16 MiB: it
    // could never be whole within the cap, so nothing more is waited for.
    conn.write_all(&[0x16, 3, 1, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff])
        .unwrap();
    closed_soon(&mut conn);
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"");
    let e = closed(&proxy);
    assert_eq!(
        (e.verdict, e.reason, e.bytes_up),
        (Verdict::Denied, Some(Reason::HelloUnreadable), 0)
    );
}

fn a_hello_that_never_ends_is_closed_at_the_cap() {
    let (port, received) = upstream(b"pong");
    let proxy = api(port);
    let mut conn = tunnel(&proxy, "api.example.com", port);
    // A handshake that says it is 16 MiB long, in records of 16 KiB that
    // each fit: the proxy holds them until 64 KiB came.
    let record = |first: bool| {
        let mut bytes = vec![0x16, 3, 1, 0x40, 0x00];
        let mut body = vec![0u8; 16 * 1024];
        if first {
            body[..4].copy_from_slice(&[0x01, 0xff, 0xff, 0xff]);
        }
        bytes.extend_from_slice(&body);
        bytes
    };
    let mut sent = 0;
    while sent < 70 * 1024 && conn.write_all(&record(sent == 0)).is_ok() {
        sent += 16 * 1024 + 5;
    }
    closed_soon(&mut conn);
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"");
    let e = closed(&proxy);
    assert_eq!(
        (e.verdict, e.reason, e.bytes_up),
        (Verdict::Denied, Some(Reason::HelloUnreadable), 0)
    );
}

fn a_hello_left_half_sent_goes_idle_frees_its_place_and_sends_nothing() {
    let (port, received) = upstream(b"pong");
    let proxy = start_with(
        &[format!("api.example.com:{port}")],
        Box::new(FakeResolver(LOCAL)),
        loopback_is_global,
        |p| {
            p.max_connections = 1;
            p.idle_timeout = Duration::from_millis(200);
        },
    );
    let mut conn = tunnel(&proxy, "api.example.com", port);
    let hello = hello::client_hello_bytes(Some("api.example.com"), false, 16_384);
    conn.write_all(&hello[..10]).unwrap();
    closed_soon(&mut conn);
    assert_eq!(received.recv_timeout(PATIENCE).unwrap(), b"");
    let e = closed(&proxy);
    assert_eq!(
        (e.verdict, e.reason, e.name_seen, e.bytes_up),
        (
            Verdict::Allowed,
            Some(Reason::Idle),
            Some(NameSeen::Incomplete),
            0
        )
    );
    let reply = send_once_free(
        &proxy.addr,
        "CONNECT other.example.com:443 HTTP/1.1\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
}

on_both_listeners!(
    an_allowed_tunnel_relays_bytes_and_is_logged,
    an_unlisted_destination_is_denied_at_once_and_logged,
    an_unreadable_policy_denies_with_its_own_reason_and_nothing_to_allow,
    an_allowed_tunnel_is_served_even_when_its_record_cannot_be_written,
    an_allowed_name_resolving_to_a_blocked_address_is_refused_before_connecting,
    plain_http_is_forwarded_in_origin_form,
    a_plain_http_connection_carries_one_request_and_its_body,
    a_second_request_sent_with_the_head_is_dropped,
    a_tunnel_keeps_what_the_client_sent_with_its_connect,
    a_plain_http_head_a_server_could_split_otherwise_is_refused_and_recorded,
    a_policy_change_applies_to_the_next_connection,
    garbage_gets_a_400_and_no_log_row,
    a_host_that_is_not_a_name_is_logged_escaped,
    a_bad_target_is_logged_without_its_user_or_query,
    a_plain_http_target_is_logged_without_its_query_or_fragment,
    a_plain_http_target_with_a_user_gets_a_400_and_no_log_row,
    an_allowed_name_that_does_not_resolve_failed_and_was_not_refused,
    connections_over_the_limit_are_turned_away,
    an_idle_tunnel_is_closed_and_frees_its_place,
    a_tunnel_that_keeps_moving_bytes_one_way_stays_open,
    plain_http_waiting_on_a_silent_server_is_closed_when_idle,
    a_resolver_that_hangs_is_cut_at_the_deadline,
    a_client_that_stops_reading_is_closed_even_while_it_sends,
    lookups_given_up_on_count_against_the_limit_until_they_return,
    a_tunnel_whose_hello_names_its_host_goes_through_with_the_name_logged,
    a_hello_split_between_the_request_and_the_tunnel_goes_up_once,
    a_tunnel_whose_hello_names_another_server_is_closed_before_it_reaches_it,
    a_server_name_is_logged_escaped_and_cut,
    a_tunnel_whose_server_speaks_first_works_and_is_logged_as_not_tls,
    a_client_done_before_it_sent_anything_still_gets_the_servers_answer,
    a_hello_with_no_name_or_ech_with_another_is_closed,
    a_hello_with_ech_and_its_own_name_is_checked_and_goes_through,
    a_tunnel_whose_tls_does_not_read_as_one_hello_is_closed,
    a_hello_that_says_it_is_longer_than_the_cap_is_closed_at_once,
    a_hello_that_never_ends_is_closed_at_the_cap,
    a_hello_left_half_sent_goes_idle_frees_its_place_and_sends_nothing,
);

/// Clients in a sandbox reach the proxy through the relay, with no DNS of
/// their own. A destination `allowed` lets through, on a server of this
/// test's, and another, as curl and Python's `urllib` send them.
mod through_the_relay {
    use super::*;
    use std::process::{Command, Output};

    const NOT_ALLOWED: &str = "denied.test";

    /// A proxy on its Unix socket with a relay in front, its port, and the
    /// server behind it.
    fn started() -> (Running, u16, u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        ON_UNIX.set(true);
        let (server, asked) =
            upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi");
        let proxy = start(
            &[
                format!("allowed.test:{server}"),
                format!("tunnel.test:{server}"),
            ],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            loopback_is_global,
        );
        let Address::Unix(socket) = proxy.addr.clone() else {
            unreachable!("started on a Unix socket");
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || crate::relay::serve(listener, &socket));
        (proxy, port, server, asked)
    }

    /// `client`, with no proxy from the environment running these tests.
    fn run(mut client: Command) -> Output {
        for name in [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
        ] {
            client.env_remove(name);
        }
        client.output().unwrap()
    }

    /// curl's status line for `url`, through the proxy at `port`, followed
    /// by its body.
    fn curl(port: u16, url: &str, tunnel: bool) -> String {
        let mut client = Command::new("curl");
        client
            .args(["--silent", "--max-time", "30", "--noproxy", ""])
            .args(["--proxy", &format!("http://127.0.0.1:{port}")])
            .args(["--write-out", "\n%{http_code}"])
            .arg(url);
        if tunnel {
            client.arg("--proxytunnel");
        }
        let out = run(client);
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// What Python's `urllib` got for `url`: its status, then its body.
    fn python(port: u16, url: &str) -> String {
        const SCRIPT: &str = r#"
import sys, urllib.error, urllib.request
proxy = urllib.request.ProxyHandler({"http": sys.argv[1]})
try:
    answer = urllib.request.build_opener(proxy).open(sys.argv[2], timeout=30)
except urllib.error.HTTPError as refused:
    answer = refused
print(answer.status, answer.read().decode())
"#;
        let mut client = Command::new("python3");
        client
            .args(["-I", "-c", SCRIPT])
            .arg(format!("http://127.0.0.1:{port}"))
            .arg(url);
        let out = run(client);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn curl_reaches_what_the_policy_allows() {
        let (_proxy, port, server, asked) = started();
        let got = curl(port, &format!("http://allowed.test:{server}/path"), false);
        assert_eq!(got, "hi\n200");
        let asked = asked.recv_timeout(PATIENCE).unwrap();
        assert!(asked.starts_with(b"GET /path HTTP/1.1\r\n"));
    }

    #[test]
    fn curl_opens_a_tunnel_to_what_the_policy_allows() {
        let (proxy, port, server, asked) = started();
        let got = curl(port, &format!("http://tunnel.test:{server}/path"), true);
        assert_eq!(got, "hi\n200");
        asked.recv_timeout(PATIENCE).unwrap();
        let log = proxy.log.0.lock().unwrap();
        assert_eq!(
            (log[0].method.as_str(), log[0].verdict),
            ("CONNECT", Verdict::Allowed)
        );
    }

    #[test]
    fn curl_gets_the_refusal_of_a_destination_the_policy_denies() {
        let (proxy, port, server, _asked) = started();
        let got = curl(port, &format!("http://{NOT_ALLOWED}:{server}/"), false);
        assert!(got.ends_with("\n403"), "{got}");
        let log = proxy.log.0.lock().unwrap();
        assert_eq!(
            (log[0].host.as_str(), log[0].reason),
            (NOT_ALLOWED, Some(Reason::NotAllowed))
        );
    }

    #[test]
    fn python_reaches_what_the_policy_allows() {
        let (_proxy, port, server, asked) = started();
        let got = python(port, &format!("http://allowed.test:{server}/path"));
        assert_eq!(got, "200 hi\n");
        let asked = asked.recv_timeout(PATIENCE).unwrap();
        assert!(asked.starts_with(b"GET /path HTTP/1.1\r\n"));
    }

    #[test]
    fn python_gets_the_refusal_of_a_destination_the_policy_denies() {
        let (proxy, port, server, _asked) = started();
        let got = python(port, &format!("http://{NOT_ALLOWED}:{server}/"));
        assert!(got.starts_with("403 "), "{got}");
        let log = proxy.log.0.lock().unwrap();
        assert_eq!(
            (log[0].host.as_str(), log[0].reason),
            (NOT_ALLOWED, Some(Reason::NotAllowed))
        );
    }
}
