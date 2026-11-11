//! The engine's network calls: the network log, denied destinations, and
//! running a sandbox's egress proxy (design §6).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::ErrorKind;
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use super::Engine;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::proxy::{ActivePolicy, Listener, Proxy, listen, listen_unix};
use crate::state::Wait;
use crate::state::sqlite::{NetLogWriter, SqliteStateStore};

impl Engine {
    /// The sandbox's connections, oldest first, from `since` on.
    pub fn net_log(&self, name: &SandboxName, since: Option<Timestamp>) -> Result<Vec<NetEvent>> {
        self.require_sandbox(name)?;
        Ok(self.state.events(name, since)?)
    }

    /// Each destination the sandbox was refused, most recent first.
    pub fn net_denied(&self, name: &SandboxName) -> Result<Vec<DeniedDestination>> {
        self.require_sandbox(name)?;
        Ok(self.state.denied(name)?)
    }

    /// Runs the sandbox's egress proxy until the process ends: on its Unix
    /// socket, and on `port` on both loopbacks unless its sessions reach it
    /// over the socket alone (ADR 0040). With `record`, it records itself
    /// once it holds the port, or the lock only one proxy holds, and its
    /// socket is open or given up on, as `proxy_socket` says. It reads the
    /// active policy for each new connection, so policy changes apply
    /// without a restart.
    pub fn run_proxy(&self, name: &SandboxName, port: u16, record: Option<&Actor>) -> Result<()> {
        let sandbox = self.record(name)?;
        self.policy(name)?;
        let store =
            |wait| SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock(), wait);
        // It only reads, which never waits for a write, nor, with a
        // connection kept open as long as the proxy runs, for another
        // command's connection to rebuild the log's index.
        let policy = ActivePolicy {
            store: store(Wait::Command),
            sandbox: name.clone(),
        };
        let _open = policy.store.keep_open()?;
        // A connection waits for its row before it is forwarded.
        let log = NetLogWriter::start(store(Wait::Command));
        let proxy = Proxy::new(name.clone(), Box::new(policy), Box::new(log));
        // Held until the process ends, as the port is.
        let (_lock, listeners) = match sandbox.backend.reaches_proxy_over_socket() {
            true => (Some(self.hold_proxy_lock(name)?), Vec::new()),
            false => (None, self.listen_on_port(name, port, sandbox.proxy_port)?),
        };
        // After the port or the lock, which only one proxy holds: so a socket
        // found here is not the running proxy's.
        let socket = self.proxy_socket(name, sandbox.backend)?;
        if let Some(by) = record {
            self.record_proxy(by, name)?;
        }
        // Serving ends only if an accept thread ended or could not start:
        // an error, so the service manager starts the proxy again.
        Err(Error::ProxyStopped {
            sandbox: name.to_string(),
            source: Arc::new(proxy).serve_all(
                listeners
                    .into_iter()
                    .map(Listener::from)
                    .chain(socket.map(Listener::from))
                    .collect(),
            ),
        })
    }

    /// The proxy's listeners at `port` on both loopbacks, or on 127.0.0.1
    /// alone where `[::1]` is not configured. When the sandbox's reserved
    /// port is taken, the error says whether by the sandbox's own proxy or
    /// by another program, and on which loopback.
    fn listen_on_port(
        &self,
        name: &SandboxName,
        port: u16,
        reserved: u16,
    ) -> Result<Vec<TcpListener>> {
        listen(port).map_err(|e| match e.source.kind() {
            // Only the sandbox's reserved port is its to recreate.
            ErrorKind::AddrInUse if port == reserved => match self.proxy_runs(name) {
                Ok(true) => Error::ProxyRuns {
                    sandbox: name.to_string(),
                    on: format!("port {port}"),
                },
                Ok(false) => Error::proxy_port_taken(name.as_str(), e.addr),
                Err(error) => error,
            },
            _ => Error::ProxyListen {
                sandbox: name.to_string(),
                addr: e.addr.to_string(),
                source: e.source,
            },
        })
    }

    /// The lock only the sandbox's running proxy holds, for a proxy that
    /// holds no port: it keeps a second proxy off the first one's socket, as
    /// the port does for a proxy that holds one.
    fn hold_proxy_lock(&self, name: &SandboxName) -> Result<File> {
        let path = self.layout.proxy_lock(name.as_str());
        let io = |source| LayoutError::Io {
            path: path.clone(),
            source,
        };
        self.layout
            .create_proxy_socket_dir(name.as_str())
            .map_err(io)?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(Error::ProxyRuns {
                sandbox: name.to_string(),
                on: "its socket".to_owned(),
            }),
            Err(TryLockError::Error(e)) => Err(io(e).into()),
        }
    }

    /// The proxy's listener on the sandbox's Unix socket, in a folder made
    /// for it. A failure is said on stderr when the sandbox's sessions do
    /// not need the socket, and is an error when they do.
    pub(super) fn proxy_socket(
        &self,
        name: &SandboxName,
        backend: BackendKind,
    ) -> Result<Option<UnixListener>> {
        let path = self.layout.proxy_socket(name.as_str());
        let opened = self
            .layout
            .create_proxy_socket_dir(name.as_str())
            .and_then(|()| listen_unix(&path));
        match opened {
            Ok(listener) => Ok(Some(listener)),
            Err(e) if !backend.reaches_proxy_over_socket() => {
                eprintln!(
                    "enclos proxy: cannot listen on {}, so sandbox {name}'s proxy serves its port alone: {e}",
                    path.display()
                );
                Ok(None)
            }
            Err(source) => Err(Error::ProxySocket {
                sandbox: name.to_string(),
                path,
                source,
            }),
        }
    }
}
