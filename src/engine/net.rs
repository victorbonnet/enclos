//! The engine's network calls: the network log, denied destinations, and
//! running a sandbox's egress proxy (design §6).

use std::io::ErrorKind;
use std::sync::Arc;

use super::Engine;
use crate::error::{Error, Result};
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::sandbox::SandboxName;
use crate::proxy::{ActivePolicy, Proxy, listen};
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

    /// Runs the sandbox's egress proxy on `port`, on both loopbacks, until
    /// the process ends. With `record`, it records itself as the sandbox's
    /// proxy once `listen` holds the port (on both loopbacks, or on
    /// 127.0.0.1 alone where `[::1]` is not configured), never before: a
    /// recorded proxy owns its port.
    /// When the sandbox's reserved port is taken, it says whether by the
    /// sandbox's own proxy or by another program, and on which loopback.
    /// It reads the active policy for each new connection, so policy
    /// changes apply without a restart.
    pub fn run_proxy(&self, name: &SandboxName, port: u16, record: Option<&Actor>) -> Result<()> {
        let reserved = self.record(name)?.proxy_port;
        self.policy(name)?;
        let store = || SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock());
        let policy = ActivePolicy {
            store: store(),
            sandbox: name.clone(),
        };
        let proxy = Proxy::new(name.clone(), Box::new(policy), Box::new(store()));
        let listeners = listen(port).map_err(|e| match e.source.kind() {
            // Only the sandbox's reserved port is its to recreate.
            ErrorKind::AddrInUse if port == reserved => match self.proxy_runs(name) {
                Ok(true) => Error::ProxyRuns {
                    sandbox: name.to_string(),
                    port,
                },
                Ok(false) => Error::proxy_port_taken(name.as_str(), e.addr),
                Err(error) => error,
            },
            _ => Error::ProxyListen {
                sandbox: name.to_string(),
                addr: e.addr.to_string(),
                source: e.source,
            },
        })?;
        if let Some(by) = record {
            self.record_proxy(by, name)?;
        }
        // Serving ends only if an accept thread ended or could not start:
        // an error, so the service manager starts the proxy again.
        Err(Error::ProxyStopped {
            sandbox: name.to_string(),
            source: Arc::new(proxy).serve_all(listeners),
        })
    }
}
