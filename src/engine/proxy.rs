//! A sandbox's proxy: started when a session needs it, or as a service
//! (ADR 0007, ADR 0021).

use std::fs::OpenOptions;
use std::net::{Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::Engine;
use super::service::PROXY_WAIT;
use crate::error::{Error, Result};
use crate::lifecycle::process::{is_same, reference_of_child};
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::state::StateLock;

/// How long the proxy has to start listening.
const PROXY_START: Duration = Duration::from_secs(5);

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
            Reached::Port(addr) => {
                TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
            }
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

    /// Starts the sandbox's proxy unless it runs already, and records it as
    /// a session, so that `sandbox stop` ends it too.
    pub(super) fn ensure_proxy(&self, lock: &StateLock, record: &SandboxRecord) -> Result<()> {
        if self.proxy_runs(&record.name)? {
            return Ok(());
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
        let reached = self.proxy_reached_at(record);
        if let Reached::Port(addr) = &reached {
            // Anything else on this port, on either loopback, would receive
            // the sandbox's traffic.
            let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port()));
            if let Some(taken) = [*addr, v6]
                .into_iter()
                .find(|a| TcpStream::connect_timeout(a, Duration::from_millis(200)).is_ok())
            {
                return Err(Error::proxy_port_taken(record.name.as_str(), taken));
            }
        }
        let child = Command::new(exe)
            .args([
                "proxy",
                "run",
                record.name.as_str(),
                "--port",
                &record.proxy_port.to_string(),
            ])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| failed(format!("could not start the proxy: {e}")))?;
        let mut child = child;
        match self.record_started_proxy(lock, record, &mut child, &reached, &log_path) {
            Ok(()) => Ok(()),
            Err(e) => Err(abandon(child, e, "the proxy")),
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
        let failed = |what: String| Error::Session { what };
        let start = Instant::now();
        loop {
            // Listening is not enough: it must be this proxy, still running.
            let exited = |child: &mut Child| -> Result<()> {
                let status = child.try_wait().map_err(|e| {
                    failed(format!("lost the proxy of sandbox {}: {e}", record.name))
                })?;
                match status {
                    None => Ok(()),
                    Some(status) => Err(failed(format!(
                        "the proxy of sandbox {} exited ({status}): {}; see {}",
                        record.name,
                        last_log_line(log_path),
                        log_path.display()
                    ))),
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
                return Err(failed(format!(
                    "the proxy of sandbox {} did not start listening on {reached}; see {}",
                    record.name,
                    log_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (version, snapshot) = self.active_policy(&record.name)?;
        let session = SessionRecord {
            id: SessionId(0),
            sandbox: record.name.clone(),
            kind: SessionKind::Proxy,
            service: None,
            version: version.version,
            snapshot: snapshot.id,
            compiled: None,
            root: reference_of_child(child)?,
            pgid: Some(child.id()),
            cgroup: None,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        };
        self.state.put_session(lock, &session)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixListener;

    /// The #119 review: a proxy that holds its port and has not opened its
    /// socket yet is not one a bubblewrap session can reach.
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
        drop(listener);
        drop(port);
        assert!(!Reached::Port(addr).answers());
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
