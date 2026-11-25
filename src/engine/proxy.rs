//! A sandbox's proxy: started when a session needs it, or as a service
//! (ADR 0007, ADR 0021).

use std::fs::OpenOptions;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::Engine;
use super::loopback::listens;
use super::service::PROXY_WAIT;
use crate::error::{Error, Result};
use crate::lifecycle::marker::spawn_unmarked;
use crate::lifecycle::process::{is_same, reference_of_child};
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// How long the proxy has to start listening.
const PROXY_START: Duration = Duration::from_secs(5);

/// How many candidate ports a Seatbelt proxy start tries when another program
/// holds its port at bind time.
const PROXY_PORT_TRIES: usize = 5;

/// The sandbox's record once its proxy runs, and whether starting the proxy
/// moved it to another port (so a profile already compiled for the old port
/// must be compiled again).
pub(super) struct ProxyReady {
    pub record: SandboxRecord,
    pub port_changed: bool,
}

/// Why [`Engine::wait_and_record_proxy`] failed.
enum ProxyStartError {
    /// The proxy exited before it was seen listening.
    Exited(Error),
    /// Timed out waiting for it to listen, or another failure.
    Other(Error),
}

impl ProxyStartError {
    fn into_error(self) -> Error {
        match self {
            ProxyStartError::Exited(e) | ProxyStartError::Other(e) => e,
        }
    }
}

/// Where the sandbox's sessions reach its proxy, so where a proxy just
/// started is seen to listen.
pub(super) enum Reached {
    /// Its port on 127.0.0.1, which it binds after `[::1]`.
    Port(SocketAddr),
    /// Its Unix socket, which it opens once it holds the lock only one proxy
    /// holds.
    Socket(PathBuf),
}

impl Reached {
    fn answers(&self) -> bool {
        match self {
            Reached::Port(addr) => listens(*addr, Duration::from_millis(200)),
            Reached::Socket(path) => UnixStream::connect(path).is_ok(),
        }
    }
}

impl std::fmt::Display for Reached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reached::Port(addr) => write!(f, "{addr}"),
            Reached::Socket(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Ends `child`, which this command started but could not record, so that
/// it does not run where no `stop` finds it; `error` stays the reason.
pub(super) fn abandon(mut child: Child, error: Error, what: &str) -> Error {
    match child.kill().and_then(|()| child.wait()) {
        Ok(_) => error,
        Err(e) => Error::CleanupFailed {
            error: Box::new(error),
            left: format!("{what} running as pid {} ({e})", child.id()),
        },
    }
}

/// The last line the proxy wrote to its log, which says why it exited: at
/// most its last 4 KiB are read.
fn last_log_line(path: &std::path::Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let tail = || -> std::io::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(4096)))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    };
    match tail() {
        Ok(text) => match text.lines().rev().find(|l| !l.trim().is_empty()) {
            Some(line) => line.trim().to_owned(),
            None => "it wrote nothing to its log".to_owned(),
        },
        Err(e) => format!("cannot read its log: {e}"),
    }
}

impl Engine {
    /// Whether the sandbox's recorded proxy still runs.
    pub(super) fn proxy_runs(&self, name: &SandboxName) -> Result<bool> {
        for s in self.state.sessions(name, true)? {
            if s.kind == SessionKind::Proxy && is_same(&s.root)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Gives the sandbox's proxy service, when one is installed, time to
    /// record itself: a proxy this command would start instead would take
    /// its port, and the service would fail at every restart. Outside the
    /// lock, which the service needs to record itself.
    pub(super) fn wait_service_proxy(&self, name: &SandboxName) -> Result<()> {
        if self.has_services(name)? {
            self.proxy_started(name, PROXY_WAIT)?;
        }
        Ok(())
    }

    /// Ensures the sandbox's proxy runs, and says whether starting it moved
    /// the sandbox to another proxy port.
    pub(super) fn ensure_proxy_for_start(
        &self,
        lock: &StateLock,
        record: &SandboxRecord,
    ) -> Result<ProxyReady> {
        let before = record.proxy_port;
        let record = self.ensure_proxy(lock, record)?;
        let port_changed = record.proxy_port != before;
        Ok(ProxyReady {
            record,
            port_changed,
        })
    }

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too. Returns the sandbox
    /// record as it stands once the proxy runs (for a Seatbelt sandbox, its
    /// `proxy_port` may have moved if another program held the old one when
    /// the proxy tried to bind).
    pub(super) fn ensure_proxy(
        &self,
        lock: &StateLock,
        record: &SandboxRecord,
    ) -> Result<SandboxRecord> {
        if self.proxy_runs(&record.name)? {
            return Ok(record.clone());
        }
        // With services installed, the proxy is the service's to start.
        if self.has_services(&record.name)? {
            return Err(Error::Session {
                what: format!(
                    "the proxy service of sandbox {} has not started; see `enclos logs {}`, or run `enclos sandbox stop {}`, then connect again, to run it without services",
                    record.name, record.name, record.name
                ),
            });
        }
        // A recorded proxy that exited, or was killed, is replaced: its
        // session ends here.
        for dead in self
            .state
            .sessions(&record.name, true)?
            .into_iter()
            .filter(|s| s.kind == SessionKind::Proxy)
        {
            self.state.end_session(lock, dead.id)?;
        }
        let failed = |what: String| Error::Session { what };
        let exe = self
            .exe
            .clone()
            .ok_or_else(|| failed("cannot find the enclos program to start the proxy".into()))?;
        let log_path = self.proxy_log(&record.name);
        if let Some(dir) = log_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|e| failed(format!("cannot open {}: {e}", log_path.display())))?;
        let spawn = |port: u16| -> Result<Child> {
            let stderr = log
                .try_clone()
                .map_err(|e| failed(format!("cannot open {}: {e}", log_path.display())))?;
            // Holding no session's marker, it never ends with one.
            spawn_unmarked(
                Command::new(&exe)
                    .args([
                        "proxy",
                        "run",
                        record.name.as_str(),
                        "--port",
                        &port.to_string(),
                    ])
                    .process_group(0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(stderr),
            )
            .map_err(|e| failed(format!("could not start the proxy: {e}")))
        };
        let reached = self.proxy_reached_at(record);
        let Reached::Port(mut addr) = reached else {
            let mut child = spawn(record.proxy_port)?;
            return match self.record_started_proxy(lock, record, &mut child, &reached, &log_path) {
                Ok(()) => Ok(record.clone()),
                Err(e) => Err(abandon(child, e, "the proxy")),
            };
        };
        // Over TCP the port can be lost between the check that made it free
        // and the proxy's bind: the proxy then exits, and the start takes the
        // next free port, saves it and starts the proxy again.
        let mut current = record.clone();
        let mut tried = vec![current.proxy_port];
        loop {
            // Anything else on this port, on either loopback, would receive
            // the sandbox's traffic.
            let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port()));
            if let Some(taken) = [addr, v6]
                .into_iter()
                .find(|a| listens(*a, Duration::from_millis(200)))
            {
                return Err(Error::proxy_port_taken(current.name.as_str(), taken));
            }
            let mut child = spawn(current.proxy_port)?;
            let exited = match self.wait_and_record_proxy(
                lock,
                &current,
                &mut child,
                &Reached::Port(addr),
                &log_path,
            ) {
                Ok(()) => return Ok(current),
                Err(ProxyStartError::Other(e)) => return Err(abandon(child, e, "the proxy")),
                Err(ProxyStartError::Exited(e)) => e,
            };
            // Only a bind that lost is retried: its port is still held now.
            let lost = tried.len() < PROXY_PORT_TRIES
                && !super::loopback::free(addr, Duration::from_millis(200));
            // A session still running keeps the profile and the proxy
            // variables it started with, so it would go on sending to the
            // old port, which another program holds: the sandbox stays on it
            // and the start fails until those sessions end.
            if lost
                && self
                    .state
                    .sessions(&current.name, true)?
                    .iter()
                    .any(|s| s.kind != SessionKind::Proxy)
            {
                return Err(abandon(
                    child,
                    Error::Session {
                        what: format!(
                            "{exited}; another program holds port {} and a session of sandbox {} still runs with it, so the sandbox keeps it: run `enclos sandbox stop {}`, then start again",
                            current.proxy_port, current.name, current.name
                        ),
                    },
                    "the proxy",
                ));
            }
            let Some(next) = lost.then(|| self.free_port_except(&tried).ok()).flatten() else {
                return Err(abandon(child, exited, "the proxy"));
            };
            let old = current.proxy_port;
            tried.push(next);
            current.proxy_port = next;
            self.state.put(lock, &current)?;
            crate::notes::say(&format!(
                "the proxy port {old} of sandbox {} was taken by another program; using {next}",
                current.name
            ));
            addr = SocketAddr::from((Ipv4Addr::LOCALHOST, next));
        }
    }

    /// Where the sandbox's sessions reach its proxy.
    pub(super) fn proxy_reached_at(&self, record: &SandboxRecord) -> Reached {
        match record.backend.reaches_proxy_over_socket() {
            true => Reached::Socket(self.layout.proxy_socket(record.name.as_str())),
            false => Reached::Port(SocketAddr::from(([127, 0, 0, 1], record.proxy_port))),
        }
    }

    /// Waits for the proxy this command started to listen where `reached`
    /// says, and records it.
    pub(super) fn record_started_proxy(
        &self,
        lock: &StateLock,
        record: &SandboxRecord,
        child: &mut Child,
        reached: &Reached,
        log_path: &std::path::Path,
    ) -> Result<()> {
        self.wait_and_record_proxy(lock, record, child, reached, log_path)
            .map_err(ProxyStartError::into_error)
    }

    /// Waits for the proxy this command started to listen where `reached`
    /// says, and records it, telling apart a proxy that exited before it
    /// listened from any other failure.
    fn wait_and_record_proxy(
        &self,
        lock: &StateLock,
        record: &SandboxRecord,
        child: &mut Child,
        reached: &Reached,
        log_path: &std::path::Path,
    ) -> std::result::Result<(), ProxyStartError> {
        let failed = |what: String| Error::Session { what };
        let start = Instant::now();
        loop {
            // Listening is not enough: it must be this proxy, still running.
            let exited = |child: &mut Child| -> std::result::Result<(), ProxyStartError> {
                let status = child.try_wait().map_err(|e| {
                    ProxyStartError::Other(failed(format!(
                        "lost the proxy of sandbox {}: {e}",
                        record.name
                    )))
                })?;
                match status {
                    None => Ok(()),
                    Some(status) => Err(ProxyStartError::Exited(failed(format!(
                        "the proxy of sandbox {} exited ({status}): {}; see {}",
                        record.name,
                        last_log_line(log_path),
                        log_path.display()
                    )))),
                }
            };
            exited(child)?;
            // Once it answers and the proxy is still running, the proxy
            // holds every listener it could. The answer itself could come
            // from another program, or proxy, that took the place just
            // before this one; this one then exits, which the second look
            // usually catches.
            if reached.answers() {
                std::thread::sleep(Duration::from_millis(50));
                exited(child)?;
                break;
            }
            if start.elapsed() > PROXY_START {
                return Err(ProxyStartError::Other(failed(format!(
                    "the proxy of sandbox {} did not start listening on {reached}; see {}",
                    record.name,
                    log_path.display()
                ))));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (version, snapshot) = self
            .active_policy(&record.name)
            .map_err(ProxyStartError::Other)?;
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: record.name.clone(),
            kind: SessionKind::Proxy,
            service: None,
            version: version.version,
            snapshot: snapshot.id,
            compiled: None,
            root: reference_of_child(child).map_err(|e| ProxyStartError::Other(e.into()))?,
            pgid: Some(child.id()),
            cgroup: None,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        };
        self.state
            .put_session(lock, &session)
            .map_err(|e| ProxyStartError::Other(e.into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::unix::net::UnixListener;

    /// Where sessions reach the proxy over its socket, the proxy is seen
    /// started once the socket answers, whatever answers on the port.
    #[test]
    fn a_proxy_answers_once_its_socket_does_too_where_sessions_use_it() {
        let port = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
        let addr = port.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.sock");
        let socket = Reached::Socket(path.clone());
        assert!(Reached::Port(addr).answers());
        assert!(!socket.answers());
        let listener = UnixListener::bind(&path).unwrap();
        assert!(socket.answers());
        // The port still answers, the socket no longer does.
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        assert!(Reached::Port(addr).answers());
        assert!(!socket.answers());
        // The socket answers, the port does not: one this test holds without
        // listening on it, which no other test can take meanwhile, unlike a
        // port let go a moment ago.
        let _listener = UnixListener::bind(&path).unwrap();
        assert!(socket.answers());
        let (closed, _held) = held_closed();
        assert!(!Reached::Port(closed).answers());
    }

    /// An address on 127.0.0.1 nothing listens on, held as long as what
    /// comes with it: the local end of a connection to a listener, which a
    /// connection to that address does not reach.
    fn held_closed() -> (SocketAddr, (TcpListener, TcpStream)) {
        // A listener of its own for each try: Linux steps through local
        // ports from a point each destination chooses, so connections to one
        // listener can all land inside the proxy range.
        let (listener, stream) = crate::test_ports::clear_of_proxies(|| {
            let listener = crate::test_ports::tcp_listener(Ipv4Addr::LOCALHOST);
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let port = stream.local_addr().unwrap().port();
            ((listener, stream), port)
        });
        (stream.local_addr().unwrap(), (listener, stream))
    }

    /// A start that fails names where the sessions reach the proxy: the
    /// socket where they use it, the port elsewhere.
    #[test]
    fn a_start_that_fails_names_the_socket_or_the_port() {
        let path = PathBuf::from("/x/proxy.sock");
        assert_eq!(Reached::Socket(path).to_string(), "/x/proxy.sock");
        let addr = SocketAddr::from(([127, 0, 0, 1], 41001));
        assert_eq!(Reached::Port(addr).to_string(), "127.0.0.1:41001");
    }
}
