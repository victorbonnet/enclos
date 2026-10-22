//! Serving connections: one thread per client connection, two while a
//! tunnel relays bytes, and one for each name lookup. Every connection the
//! proxy decides on gets one network log record, written at the decision.
//! If that write fails, the proxy says so on its standard error and goes on
//! as if it had succeeded: an allowed connection is served without a record
//! (ADR 0027 proposes refusing it instead).

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::Proxy;
use super::decide::{Destination, allowed, validated};
use super::hello::{self, FirstBytes};
use super::request::{Request, origin_head, parse, read_head};
use crate::model::net::{NameSeen, NetEvent, Reason, Verdict, destination};
use crate::model::now;

/// How long a client has to send its whole request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait before accepting again after accepting failed, such as
/// when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The answer to a connection over the proxy's limit.
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 56\r\nConnection: close\r\n\r\nenclos: too many connections at once from this sandbox.\n";

/// Tells [`until_one_ends`] that a thread ended, however it ended. A panic
/// unwinds past any code after `work`, so only a drop signals it; without
/// that, the other listeners would go on serving while the dead one's
/// address at the port is free for another program to take.
struct Ended(mpsc::Sender<()>);

impl Drop for Ended {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// Runs `work` on each item, each on its own accept thread, and returns
/// once any of them ends, by returning or by panicking, or a thread cannot
/// start.
pub(super) fn until_one_ends<T: Send + 'static>(
    items: Vec<T>,
    work: impl Fn(T) + Clone + Send + 'static,
) -> io::Error {
    let (ended, any_ended) = mpsc::channel();
    for item in items {
        let ended = Ended(ended.clone());
        let work = work.clone();
        let started = thread::Builder::new()
            .name("enclos-proxy-accept".into())
            .spawn(move || {
                let _ended = ended;
                work(item);
            });
        if let Err(e) = started {
            return e;
        }
    }
    drop(ended);
    let _ = any_ended.recv();
    io::Error::other("it stopped accepting connections")
}

impl Proxy {
    /// Serves every listener the same way, with one connection limit, until
    /// the process ends. Returns only if one of them stopped accepting, or
    /// an accept thread could not start: an error, so the service manager
    /// starts the proxy again.
    pub fn serve_all(self: &Arc<Self>, listeners: Vec<TcpListener>) -> io::Error {
        let proxy = Arc::clone(self);
        until_one_ends(listeners, move |listener| proxy.accept(listener))
    }

    /// Accepts connections on `listener`, each on its own thread.
    fn accept(self: &Arc<Self>, listener: TcpListener) {
        for client in listener.incoming() {
            let Ok(mut client) = client else {
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            };
            let Some(slot) = Slot::take(&self.open, self.max_connections) else {
                let _ = client.write_all(BUSY);
                continue;
            };
            let proxy = Arc::clone(self);
            let started = thread::Builder::new().spawn(move || {
                let _slot = slot;
                proxy.handle(client)
            });
            if let Err(e) = started {
                eprintln!("enclos proxy: cannot start a thread for a connection: {e}");
            }
        }
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
            name_seen: None,
            server_name: None,
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
                    "enclos proxy: could not log a connection to {}: {e}; {} it without a record",
                    destination(&event.host, event.port),
                    match event.verdict {
                        Verdict::Allowed => "serving",
                        Verdict::Denied => "refusing",
                    }
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
            event.host = loggable_host(host);
        })?;
        event.host = dest.host.clone();

        let policy = self.policy.policy().map_err(|e| {
            eprintln!("enclos proxy: cannot read the active policy, denying: {e}");
            Reason::PolicyUnreadable
        })?;
        if !allowed(&policy, &dest) {
            return Err(Reason::NotAllowed);
        }
        // Refused once the destination is known, so the refusal is recorded.
        if let Request::Http { body: None, .. } = request {
            return Err(Reason::BadRequest);
        }
        // From here on the policy allows the destination: a failure to reach
        // it is not a refusal.
        event.verdict = Verdict::Allowed;
        // Resolving and connecting share one deadline.
        let deadline = Instant::now() + self.connect_timeout;
        let resolved = match dest.ip {
            Some(ip) => vec![ip],
            None => self
                .lookup(&dest.host, dest.port, deadline)
                .map_err(|failed| {
                    self.report(&dest.host, failed);
                    Reason::ResolveFailed
                })?,
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
    /// names that never resolve cannot pile up threads: while `max_lookups`
    /// are running, the next one fails right away.
    fn lookup(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, LookupFailed> {
        let place = Slot::take(&self.lookups, self.max_lookups).ok_or(LookupFailed::Full)?;
        self.lookups_full.store(false, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        let resolver = Arc::clone(&self.resolver);
        let name = host.to_owned();
        thread::Builder::new()
            .name("enclos-proxy-resolve".into())
            .spawn(move || {
                let _place = place;
                let _ = tx.send(resolver.resolve(&name, port));
            })
            .map_err(LookupFailed::NoThread)?;
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(answer) => answer.map_err(|_| LookupFailed::Resolver),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(LookupFailed::TimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(LookupFailed::Lost),
        }
    }

    /// Says on the proxy's stderr why a lookup failed, when the cause is on
    /// the host rather than the name: the network log records all of them
    /// alike, as `resolve-failed`.
    fn report(&self, host: &str, failed: LookupFailed) {
        match failed {
            // The resolver's own answer, such as no such name.
            LookupFailed::Resolver => {}
            LookupFailed::Full => {
                // Once until a lookup starts again, not for every connection.
                if !self.lookups_full.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "enclos proxy: {} lookups are still waiting on the host's resolver; new lookups fail as resolve-failed until one returns",
                        self.max_lookups
                    );
                }
            }
            LookupFailed::NoThread(e) => {
                eprintln!("enclos proxy: cannot start a thread to look up {host}: {e}");
            }
            LookupFailed::TimedOut => eprintln!(
                "enclos proxy: the host's resolver did not answer for {host} within {:?}",
                self.connect_timeout
            ),
            LookupFailed::Lost => {
                eprintln!("enclos proxy: the lookup of {host} ended without an answer");
            }
        }
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

/// What the network log keeps of a host the proxy could not parse: the
/// text after the last `@` and before the first `/`, `\`, `?` or `#`. A
/// user and password, a path, a query or a fragment may hold a secret, so
/// they are dropped. Nothing is kept when an `@` comes after that cut,
/// since the user part may not end where it seems, or when the host holds
/// a `%`, since percent-encoding can hide any of these delimiters and no
/// host name or address contains one. The result is shown later in a
/// terminal on the host, so nothing the client wrote may reach it
/// unescaped.
fn loggable_host(host: &str) -> String {
    if host.contains('%') {
        return "<invalid>".to_owned();
    }
    let end = host.find(['/', '\\', '?', '#']).unwrap_or(host.len());
    let (authority, rest) = host.split_at(end);
    let name = authority
        .rsplit_once('@')
        .map_or(authority, |(_, name)| name);
    if name.is_empty() || rest.contains('@') {
        return "<invalid>".to_owned();
    }
    name.escape_default().take(255).collect()
}

/// Why a lookup gave no addresses.
enum LookupFailed {
    /// The resolver answered with an error, such as no such name.
    Resolver,
    /// `max_lookups` lookups are still running, so this one never started.
    Full,
    /// No thread could be started for it.
    NoThread(io::Error),
    /// The resolver did not answer before the deadline.
    TimedOut,
    /// Its thread ended without an answer.
    Lost,
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
/// the connection ends or hits the idle limit: no byte moved either way, or
/// a peer read nothing, for `limit`. Adds the bytes moved to `event`, and
/// the reason `idle` when the proxy closed it for that.
fn forward(
    client: &TcpStream,
    upstream: &TcpStream,
    request: Request,
    early: &[u8],
    limit: Duration,
    event: &mut NetEvent,
) {
    // A peer that stops reading holds up a write no longer than the limit.
    for stream in [client, upstream] {
        if let Err(e) = stream.set_write_timeout(Some(limit)) {
            eprintln!(
                "enclos proxy: cannot set a timeout on a connection to {}: {e}",
                event.host
            );
            return;
        }
    }
    // A plain-HTTP client closed on before any answer is told why; a
    // tunnel's client already had its `200`.
    let mut unanswered = None;
    // How much more of the client's bytes go upstream: a tunnel's all of
    // them, a plain-HTTP request's only its body, which `open` made sure
    // the head gives.
    let mut room = None;
    // A tunnel's first bytes, held for the server name check: those the
    // client sent with its request, to which it adds.
    let mut held = None;
    let mut first = match request {
        Request::Connect { .. } => {
            let mut client = client;
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .is_err()
            {
                return;
            }
            held = Some(early.to_vec());
            Vec::new()
        }
        Request::Http {
            method,
            path,
            version,
            headers,
            body,
            ..
        } => {
            room = Some(body.unwrap_or(0));
            let dest = destination(&event.host, event.port);
            unanswered = Some(response(
                "504 Gateway Timeout",
                &format!(
                    "enclos: {dest} sent no answer within the proxy's idle limit, so the proxy closed the connection (idle).\n"
                ),
            ));
            let body = body.unwrap_or(0);
            origin_head(
                &method,
                &path,
                &version,
                &headers,
                &event.host,
                event.port,
                body,
            )
            .into_bytes()
        }
    };
    // Sent with the head, past the body: the client is done already.
    let done = room.is_some_and(|room| early.len() as u64 > room);
    if let Some(room) = &mut room {
        let body = early
            .len()
            .min(usize::try_from(*room).unwrap_or(usize::MAX));
        *room -= body as u64;
        first.extend_from_slice(&early[..body]);
    }
    let mut writer = upstream;
    if writer.write_all(&first).is_err() {
        return;
    }
    event.bytes_up += first.len() as u64;
    if done {
        let _ = upstream.shutdown(Shutdown::Write);
    }
    let check = held.map(|held| NameCheck {
        host: event.host.clone(),
        held,
    });
    let relayed = relay(client, upstream, limit, unanswered.as_deref(), room, check);
    event.bytes_up += relayed.up;
    event.bytes_down += relayed.down;
    if relayed.went_idle {
        event.reason = Some(Reason::Idle);
    }
    if let Some(checked) = relayed.checked {
        event.name_seen = Some(checked.seen);
        event.server_name = checked.name;
        if let Some(reason) = checked.refused {
            event.verdict = Verdict::Denied;
            event.reason = Some(reason);
        }
    }
}

/// What a relay moved, whether the proxy ended it for the idle limit, and
/// what the server name check saw.
struct Relayed {
    up: u64,
    down: u64,
    went_idle: bool,
    checked: Option<Checked>,
}

/// The server name check of a tunnel (design §6): the host it was opened
/// for, and the client's first bytes so far.
struct NameCheck {
    host: String,
    held: Vec<u8>,
}

/// What the server name check made of a tunnel's first bytes.
struct Checked {
    seen: NameSeen,
    /// The server name its ClientHello showed.
    name: Option<String>,
    /// Why the tunnel was closed, when it was.
    refused: Option<Reason>,
}

impl Checked {
    /// What `hello`, read from the client's first bytes, says about a
    /// tunnel opened for `host`; none while it is incomplete.
    fn of(hello: FirstBytes, host: &str) -> Option<Checked> {
        let checked = |seen, name, refused| {
            Some(Checked {
                seen,
                name,
                refused,
            })
        };
        match hello {
            FirstBytes::Incomplete => None,
            FirstBytes::NotTls => checked(NameSeen::NotTls, None, None),
            FirstBytes::Unreadable => {
                checked(NameSeen::Unreadable, None, Some(Reason::HelloUnreadable))
            }
            // The name shown is the public one, which says nothing of the
            // server asked for: the host and address were checked already.
            FirstBytes::ClientHello {
                server_name,
                encrypted: true,
            } => checked(NameSeen::Encrypted, server_name, None),
            FirstBytes::ClientHello {
                server_name: None, ..
            } => checked(NameSeen::NoName, None, None),
            FirstBytes::ClientHello {
                server_name: Some(name),
                ..
            } => {
                let refused = (!hello::same_host(&name, host)).then_some(Reason::NameMismatch);
                checked(NameSeen::Name, Some(name), refused)
            }
        }
    }
}

/// When bytes last moved through a connection, either way, as both copies
/// of a relay see it, and whether one of them closed it for the idle limit.
struct Activity {
    start: Instant,
    /// Milliseconds from `start` to the last move.
    last: AtomicU64,
    went_idle: AtomicBool,
}

impl Activity {
    fn new() -> Activity {
        Activity {
            start: Instant::now(),
            last: AtomicU64::new(0),
            went_idle: AtomicBool::new(false),
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

    fn close_idle(&self) {
        self.went_idle.store(true, Ordering::Relaxed);
    }

    fn went_idle(&self) -> bool {
        self.went_idle.load(Ordering::Relaxed)
    }
}

/// Copies bytes both ways. When the client is done, the server is told so
/// and may still answer; when the server is done, the connection ends; when
/// it hits the idle limit, both sides are closed, and a client that got no
/// byte back is first sent `unanswered`, when given. At most `room` bytes
/// go up, when given.
///
/// With `check`, the client's bytes go up only once its first ones show
/// what server it asks for, and not at all when they name another than the
/// tunnel's host: both sides are then closed. The server's bytes come down
/// from the start, so a protocol in which the server speaks first works.
fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    limit: Duration,
    unanswered: Option<&str>,
    room: Option<u64>,
    check: Option<NameCheck>,
) -> Relayed {
    let activity = Activity::new();
    thread::scope(|s| {
        let up = thread::Builder::new().spawn_scoped(s, || {
            let (checked, mut moved, go_on) = match check {
                Some(check) => {
                    let (checked, moved) = check_name(client, upstream, check, &activity, limit);
                    let go_on = checked.as_ref().is_some_and(|c| c.refused.is_none());
                    (checked, moved, go_on)
                }
                None => (None, 0, true),
            };
            if go_on {
                moved += copy(client, upstream, &activity, limit, room);
            }
            let how = match (activity.went_idle(), go_on) {
                (false, true) => Shutdown::Write,
                _ => Shutdown::Both,
            };
            let _ = upstream.shutdown(how);
            if !go_on {
                // Ends the copy down too: nothing of this tunnel goes on.
                let _ = client.shutdown(Shutdown::Both);
            }
            (moved, checked)
        });
        let down = match up {
            Ok(_) => copy(upstream, client, &activity, limit, None),
            Err(_) => 0,
        };
        // Nothing went down yet, so the client's send buffer is empty and
        // this short answer does not wait on the client.
        if let Some(answer) = unanswered
            && down == 0
            && activity.went_idle()
        {
            let _ = (&*client).write_all(answer.as_bytes());
        }
        // Ends the client side too, which also ends the copy reading it.
        let _ = client.shutdown(Shutdown::Both);
        let (up, checked) = up.map_or((0, None), |up| up.join().unwrap_or((0, None)));
        Relayed {
            up,
            down,
            went_idle: activity.went_idle(),
            checked,
        }
    })
}

/// Reads the client's first bytes until they show what server it asks
/// for, or [`hello::MAX_HELLO`] of them do not, and sends them upstream
/// unless the check refuses them. Returns what it made of them (none when
/// the client stopped, failed or went idle first) and the bytes sent.
fn check_name(
    mut client: &TcpStream,
    upstream: &TcpStream,
    check: NameCheck,
    activity: &Activity,
    limit: Duration,
) -> (Option<Checked>, u64) {
    let NameCheck { host, mut held } = check;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let hello = match hello::parse(&held) {
            FirstBytes::Incomplete if held.len() >= hello::MAX_HELLO => FirstBytes::Unreadable,
            hello => hello,
        };
        if let Some(checked) = Checked::of(hello, &host) {
            let mut moved = 0;
            if checked.refused.is_none() {
                // A failed write ends the copy that follows as soon as it starts.
                let _ = write_counted(upstream, &held, activity, &mut moved);
            }
            return (Some(checked), moved);
        }
        let quiet = activity.quiet();
        if quiet >= limit {
            activity.close_idle();
            return (None, 0);
        }
        // As `copy` waits: at most until the connection would turn idle.
        if let Err(e) = client.set_read_timeout(Some(limit - quiet))
            && e.kind() != io::ErrorKind::InvalidInput
        {
            return (None, 0);
        }
        match client.read(&mut buf) {
            Ok(0) => return (None, 0),
            Ok(read) => {
                activity.moved();
                held.extend_from_slice(&buf[..read]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted || timed_out(&e) => {}
            Err(_) => return (None, 0),
        }
    }
}

/// Copies until the reader ends, either side fails, or the connection hits
/// the idle limit: nothing moved either way for `limit`, or `to` read
/// nothing for that long. Returns the bytes that reached `to`, also when an
/// error, such as a reset, ended it.
///
/// With `room`, only that many bytes reach `to`. Once `from` sends more, a
/// plain-HTTP client's second request, which could name another site on the
/// same address, `to` is told the client is done, and still answers the
/// first; what `from` sends from then on is read and dropped, and is no
/// activity. Read, so that closing `from` later does not reset it and lose
/// the answer on its way.
fn copy(
    mut from: &TcpStream,
    to: &TcpStream,
    activity: &Activity,
    limit: Duration,
    mut room: Option<u64>,
) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut moved = 0;
    // Whether `to` was told the client is done.
    let mut told = false;
    loop {
        let quiet = activity.quiet();
        if quiet >= limit {
            activity.close_idle();
            return moved;
        }
        // Waits at most until the connection would turn idle; if the other
        // copy moved bytes meanwhile, the next turn of the loop waits again.
        // macOS refuses the option once the connection is closed both ways
        // (EINVAL), while what it received can still be read, and a read
        // then cannot wait: stopping here would lose a server's answer.
        if let Err(e) = from.set_read_timeout(Some(limit - quiet))
            && e.kind() != io::ErrorKind::InvalidInput
        {
            return moved;
        }
        match from.read(&mut buf) {
            Ok(0) => return moved,
            Ok(read) => {
                let n = match &mut room {
                    Some(room) => {
                        let n = read.min(usize::try_from(*room).unwrap_or(usize::MAX));
                        *room -= n as u64;
                        n
                    }
                    None => read,
                };
                if n > 0 {
                    activity.moved();
                    if let Err(e) = write_counted(to, &buf[..n], activity, &mut moved) {
                        // A write times out after the limit: `to` stopped reading.
                        if timed_out(&e) {
                            activity.close_idle();
                        }
                        return moved;
                    }
                }
                if n < read && !told {
                    let _ = to.shutdown(Shutdown::Write);
                    told = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted || timed_out(&e) => {}
            Err(_) => return moved,
        }
    }
}

/// Writes all of `buf`, adding to `moved` what each write sent, so a write
/// cut short still counts what got through. Each write is activity, so the
/// other copy does not count the time a slow write took as quiet.
fn write_counted(
    mut to: &TcpStream,
    mut buf: &[u8],
    activity: &Activity,
    moved: &mut u64,
) -> io::Result<()> {
    while !buf.is_empty() {
        match to.write(buf) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                *moved += n as u64;
                activity.moved();
                buf = &buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
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
            "enclos: the proxy cannot serve this request. It serves CONNECT host:port, and plain-HTTP requests with an absolute URL, header lines of the form `Name: value` and, for a body, one Content-Length (no Transfer-Encoding).\n".to_owned(),
        ),
        (_, Reason::PolicyUnreadable) => {
            let sandbox = &event.sandbox;
            (
                "403 Forbidden",
                format!(
                    "enclos: the proxy cannot read this sandbox's policy, so it refuses every destination for now, {dest} included. There is nothing to allow: see why from the host with `enclos logs {sandbox}`.\n"
                ),
            )
        }
        _ => (
            "403 Forbidden",
            format!(
                "enclos: this sandbox's policy does not allow {dest} ({reason}). Allow it from the host with `enclos policy allow`.\n"
            ),
        ),
    };
    client.write_all(response(status, &body).as_bytes())
}

/// A whole plain-text HTTP response, after which the proxy closes.
fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::loggable_host;

    /// A server that answered and closed after the proxy told it the client
    /// was done: its connection is closed both ways, and its answer is
    /// still copied.
    #[test]
    fn an_answer_from_a_connection_closed_both_ways_is_copied() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpListener, TcpStream};
        use std::time::Duration;

        let pair = || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (far, _) = listener.accept().unwrap();
            (near, far)
        };
        let (upstream, mut server) = pair();
        let (client, mut reader) = pair();
        upstream.shutdown(Shutdown::Write).unwrap();
        server.write_all(b"answer").unwrap();
        drop(server);
        // Time for the server's end to arrive: on macOS, the socket then
        // refuses a read timeout.
        std::thread::sleep(Duration::from_millis(100));

        let activity = super::Activity::new();
        let moved = super::copy(&upstream, &client, &activity, Duration::from_secs(5), None);
        assert_eq!(moved, 6);
        drop(client);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"answer");
    }

    #[test]
    fn a_bad_host_keeps_only_what_can_be_a_host() {
        let long = "a".repeat(300);
        let cases = [
            ("user:secret@api.example.com", "api.example.com"),
            ("token@api.example.com", "api.example.com"),
            ("user:p@ss@api.example.com", "api.example.com"),
            ("api.example.com?token=secret", "api.example.com"),
            ("api.example.com#secret", "api.example.com"),
            ("api.example.com/secret", "api.example.com"),
            ("api.example.com\\secret", "api.example.com"),
            ("user:secret@::1", "::1"),
            ("user:secret@evil\x1bhost/secret", "evil\\u{1b}host"),
            (&format!("{long}?secret"), &long[..255]),
            // Nothing that could be a host is left: a fixed placeholder.
            ("user:secret@", "<invalid>"),
            ("?token=secret", "<invalid>"),
            // Where the user part ends is unclear: none of it is kept.
            ("user:se/cret@api.example.com", "<invalid>"),
            ("api.example.com?to@ken=secret", "<invalid>"),
            // Percent-encoding can hide any delimiter, and no host holds a `%`.
            ("user%3Asecret%40api.example.com", "<invalid>"),
            ("token%40api.example.com", "<invalid>"),
            ("api.example.com%3Ftoken%3Dsecret", "<invalid>"),
        ];
        for (host, logged) in cases {
            assert_eq!(loggable_host(host), logged, "{host}");
            assert!(!loggable_host(host).contains("secret"), "{host}");
        }
    }
}
