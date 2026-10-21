//! The engine's network calls: the network log, denied destinations, and
//! running a sandbox's egress proxy (design §6).

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use super::Engine;
use crate::error::{Error, Result};
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::sandbox::SandboxName;
use crate::proxy::{ActivePolicy, Proxy};
use crate::state::sqlite::SqliteStateStore;

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

    /// Runs the sandbox's egress proxy on `addr` until the process ends.
    /// With `record`, it records itself as the sandbox's proxy once it holds
    /// the port, never before: a recorded proxy owns its port. When the
    /// sandbox's reserved port is taken, it says whether by the sandbox's
    /// own proxy or by another program.
    /// It reads the active policy for each new connection, so policy
    /// changes apply without a restart.
    pub fn run_proxy(
        &self,
        name: &SandboxName,
        addr: SocketAddr,
        record: Option<&Actor>,
    ) -> Result<()> {
        let reserved = self.record(name)?.proxy_port;
        self.policy(name)?;
        let store = || SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock());
        let policy = ActivePolicy {
            store: store(),
            sandbox: name.clone(),
        };
        let proxy = Proxy::new(name.clone(), Box::new(policy), Box::new(store()));
        let socket = match TcpListener::bind(addr) {
            Ok(socket) => socket,
            // Only the sandbox's reserved port is its to recreate.
            Err(e) if e.kind() == ErrorKind::AddrInUse && addr.port() == reserved => {
                let (sandbox, port) = (name.to_string(), reserved);
                return Err(if self.proxy_runs(name)? {
                    Error::ProxyRuns { sandbox, port }
                } else {
                    Error::ProxyPortTaken { sandbox, port }
                });
            }
            Err(source) => {
                return Err(Error::ProxyListen {
                    sandbox: name.to_string(),
                    addr: addr.to_string(),
                    source,
                });
            }
        };
        if let Some(by) = record {
            self.record_proxy(by, name)?;
        }
        let stopped = |source| Error::ProxyStopped {
            sandbox: name.to_string(),
            source,
        };
        let _ = Arc::new(proxy).serve(socket).map_err(stopped)?.join();
        // Serving ends only if the accept loop died: an error, so the
        // service manager starts the proxy again.
        Err(stopped(std::io::Error::other(
            "it stopped accepting connections",
        )))
    }
}
