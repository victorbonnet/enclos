//! A tunnel once it is open: the server name check, the bytes each way,
//! and how long it may stay quiet (design §6).

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::hello::{self, FirstBytes};
use crate::model::net::{NameSeen, Reason};

/// What a relay moved, whether the proxy ended it for the idle limit, and
/// what the server name check made of the tunnel.
pub(super) struct Relayed {
    pub(super) up: u64,
    pub(super) down: u64,
    pub(super) went_idle: bool,
    pub(super) checked: Option<Checked>,
}

/// The server name check of a tunnel (design §6): the host it was opened
/// for, and the client's first bytes so far.
pub(super) struct NameCheck {
    pub(super) host: String,
    pub(super) held: Vec<u8>,
}

/// What the server name check made of a tunnel's first bytes, and why it
/// closed the tunnel, when it did.
pub(super) struct Checked {
    pub(super) seen: NameSeen,
    pub(super) refused: Option<Reason>,
}

impl Checked {
    /// What `hello`, read from the client's first bytes, says about a
    /// tunnel opened for `host`; none while it is incomplete.
    fn of(hello: FirstBytes, host: &str) -> Option<Checked> {
        let checked = |seen, refused| Some(Checked { seen, refused });
        match hello {
            FirstBytes::Incomplete { .. } => None,
            FirstBytes::NotTls => checked(NameSeen::NotTls, None),
            FirstBytes::Unreadable => checked(NameSeen::Unreadable, Some(Reason::HelloUnreadable)),
            // Compared whether or not the hello carries ECH: browsers send
            // an ECH extension of no use (GREASE) with the name they ask for.
            FirstBytes::ClientHello {
                server_name: Some(name),
                ..
            } if hello::same_host(&name, host) => {
                checked(NameSeen::Name(NameSeen::shown(&name)), None)
            }
            // Under ECH the name shown is the public name of the server
            // that decrypts the real one: the name asked for cannot be
            // compared, so the tunnel is closed, as one that only claims ECH
            // to skip the check is (design §6).
            FirstBytes::ClientHello {
                server_name,
                encrypted: true,
            } => checked(
                NameSeen::Encrypted {
                    public: server_name.as_deref().map(NameSeen::shown),
                },
                Some(Reason::EncryptedHello),
            ),
            FirstBytes::ClientHello {
                server_name: Some(name),
                ..
            } => checked(
                NameSeen::Name(NameSeen::shown(&name)),
                Some(Reason::NameMismatch),
            ),
            // A client names no server for an address, and a tunnel opened
            // for a host name that names none would reach whichever site the
            // address serves by default (design §6).
            FirstBytes::ClientHello {
                server_name: None, ..
            } => checked(
                NameSeen::NoName,
                (!is_address(host)).then_some(Reason::NoServerName),
            ),
        }
    }
}

/// Whether a tunnel's host is an address (`10.1.2.3`, `[::1]`), for which
/// a client names no server, rather than a host name.
fn is_address(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>().is_ok()
}

/// How long a tunnel's first bytes may take to show what server it asks
/// for, however they trickle in: a ClientHello comes as the connection
/// opens, and a client that keeps sending a byte now and then must not hold
/// the check open, its bytes and its log record, for days.
const HELLO_WAIT: Duration = Duration::from_secs(30);

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
/// what server it asks for, and not at all when the check refuses them or
/// never decides: both sides are then closed. A client done before it sent
/// anything is as any client done. The server's bytes come down from the
/// start, so a protocol in which the server speaks first works.
pub(super) fn relay(
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
            // Whether the client's bytes go on up, and whether the client
            // was done before the check could see anything.
            let (checked, mut moved, go_on, done) = match check {
                None => (None, 0, true, false),
                Some(check) => {
                    match check_name(client, upstream, check, &activity, limit, HELLO_WAIT) {
                        Held::Decided {
                            checked,
                            sent,
                            passed,
                        } => {
                            let go_on = passed && checked.refused.is_none();
                            (Some(checked), sent, go_on, false)
                        }
                        Held::ClientDone => (None, 0, false, true),
                        Held::Stopped { held } => {
                            let checked = held.then_some(Checked {
                                seen: NameSeen::Incomplete,
                                refused: None,
                            });
                            (checked, 0, false, false)
                        }
                    }
                }
            };
            if go_on {
                moved += copy(client, upstream, &activity, limit, room);
            }
            // The server is told the client is done, and may still answer,
            // unless the proxy ends the tunnel.
            let refused = !(go_on || done);
            let _ = upstream.shutdown(if activity.went_idle() || refused {
                Shutdown::Both
            } else {
                Shutdown::Write
            });
            if refused {
                // Ends the copy down too: nothing of this tunnel goes on. An
                // idle one is ended below, once a plain-HTTP client was told.
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
        let (up, checked) = match up {
            Err(_) => (0, None),
            Ok(up) => up.join().unwrap_or_else(|_| {
                eprintln!("enclos proxy: the copy of a tunnel's bytes to its server failed");
                (0, None)
            }),
        };
        Relayed {
            up,
            down,
            went_idle: activity.went_idle(),
            checked,
        }
    })
}

/// How the server name check of a tunnel ended.
enum Held {
    /// It decided: what it made of the first bytes, how many of them went
    /// up, and whether all that were to go did.
    Decided {
        checked: Checked,
        sent: u64,
        passed: bool,
    },
    /// The client was done before it sent anything.
    ClientDone,
    /// The client stopped, failed or went idle first; `held` says whether
    /// it had sent anything, none of which went up.
    Stopped { held: bool },
}

/// Reads the client's first bytes until they show what server it asks
/// for, or [`hello::MAX_HELLO`] of them do not, and sends them upstream
/// unless the check refuses them; stopped, as idle, at `deadline` (the
/// proxy's is [`HELLO_WAIT`]) whatever moved.
fn check_name(
    mut client: &TcpStream,
    upstream: &TcpStream,
    check: NameCheck,
    activity: &Activity,
    limit: Duration,
    deadline: Duration,
) -> Held {
    let NameCheck { host, mut held } = check;
    let began = Instant::now();
    let mut buf = [0u8; 16 * 1024];
    // Read again only once as many bytes as it waits for have come.
    let mut needed = 0;
    loop {
        if held.len() >= needed {
            let hello = match hello::parse(&held) {
                // One that would need more than the most held is unreadable
                // now, not once that much came.
                FirstBytes::Incomplete { needed }
                    if needed > hello::MAX_HELLO || held.len() >= hello::MAX_HELLO =>
                {
                    FirstBytes::Unreadable
                }
                FirstBytes::Incomplete { needed: more } => {
                    needed = more;
                    FirstBytes::Incomplete { needed: more }
                }
                hello => hello,
            };
            if let Some(checked) = Checked::of(hello, &host) {
                let mut sent = 0;
                let mut passed = true;
                if checked.refused.is_none()
                    && let Err(e) = write_counted(upstream, &held, activity, &mut sent)
                {
                    // As in `copy`: a write that times out is a server that
                    // stopped reading.
                    if timed_out(&e) {
                        activity.close_idle();
                    }
                    passed = false;
                }
                return Held::Decided {
                    checked,
                    sent,
                    passed,
                };
            }
        }
        let stopped = Held::Stopped {
            held: !held.is_empty(),
        };
        let quiet = activity.quiet();
        let left = deadline.saturating_sub(began.elapsed());
        if quiet >= limit || left.is_zero() {
            activity.close_idle();
            return stopped;
        }
        // As `copy` waits: at most until the connection would turn idle, and
        // never past the check's own deadline.
        if let Err(e) = client.set_read_timeout(Some((limit - quiet).min(left)))
            && e.kind() != io::ErrorKind::InvalidInput
        {
            eprintln!("enclos proxy: cannot wait on the client of a tunnel to {host}: {e}");
            return stopped;
        }
        // No more than the most it holds.
        let room = hello::MAX_HELLO
            .saturating_sub(held.len())
            .clamp(1, buf.len());
        match client.read(&mut buf[..room]) {
            Ok(0) if held.is_empty() => return Held::ClientDone,
            Ok(0) => return stopped,
            Ok(read) => {
                activity.moved();
                held.extend_from_slice(&buf[..read]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted || timed_out(&e) => {}
            Err(e) => {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) {
                    eprintln!("enclos proxy: lost the client of a tunnel to {host}: {e}");
                }
                return stopped;
            }
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

#[cfg(test)]
mod tests {

    /// What a hello naming no server, or under ECH another, comes to: for
    /// a host name, closed; for an address, which a client names no server
    /// for, no name is no refusal.
    #[test]
    fn no_name_is_refused_for_a_host_name_and_not_for_an_address() {
        use super::{Checked, FirstBytes, Reason};
        let no_name = || FirstBytes::ClientHello {
            server_name: None,
            encrypted: false,
        };
        let refused = |hello, host| Checked::of(hello, host).unwrap().refused;
        assert_eq!(
            refused(no_name(), "api.example.com"),
            Some(Reason::NoServerName)
        );
        assert_eq!(refused(no_name(), "93.184.215.14"), None);
        assert_eq!(refused(no_name(), "[2606:4700::1]"), None);
        let ech = |name: &str| FirstBytes::ClientHello {
            server_name: Some(name.to_owned()),
            encrypted: true,
        };
        assert_eq!(
            refused(ech("public.example.net"), "api.example.com"),
            Some(Reason::EncryptedHello)
        );
        assert_eq!(refused(ech("api.example.com"), "api.example.com"), None);
        // ECH with no visible name: the name asked for is all inside, so it
        // is closed, for an address too.
        let ech_no_name = || FirstBytes::ClientHello {
            server_name: None,
            encrypted: true,
        };
        for host in ["93.184.215.14", "api.example.com"] {
            assert_eq!(
                refused(ech_no_name(), host),
                Some(Reason::EncryptedHello),
                "{host}"
            );
        }
        // A tunnel opened for an address matches no host name.
        let named = |name: &str| FirstBytes::ClientHello {
            server_name: Some(name.to_owned()),
            encrypted: false,
        };
        for host in ["93.184.215.14", "[2606:4700::1]"] {
            assert_eq!(
                refused(named("evil.example.com"), host),
                Some(Reason::NameMismatch),
                "{host}"
            );
        }
    }

    /// A client that keeps sending a byte now and then, never a whole
    /// hello, is stopped at the check's deadline, though never idle.
    #[test]
    fn a_hello_trickled_in_is_stopped_at_the_deadline() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        let pair = || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (far, _) = listener.accept().unwrap();
            (near, far)
        };
        let (mut client, proxied) = pair();
        let (upstream, _server) = pair();
        let trickle = std::thread::spawn(move || {
            // A TLS record header saying more is to come, then a byte at a
            // time.
            let _ = client.write_all(&[0x16, 3, 1, 0x40, 0]);
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(100));
                if client.write_all(&[1]).is_err() {
                    break;
                }
            }
        });
        let activity = super::Activity::new();
        let check = super::NameCheck {
            host: "api.example.com".into(),
            held: Vec::new(),
        };
        let began = Instant::now();
        let held = super::check_name(
            &proxied,
            &upstream,
            check,
            &activity,
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        assert!(matches!(held, super::Held::Stopped { held: true }));
        assert!(
            began.elapsed() < Duration::from_secs(3),
            "{:?}",
            began.elapsed()
        );
        drop(proxied);
        trickle.join().unwrap();
    }

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
}
