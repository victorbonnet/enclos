//! The engine's network calls: the network log, denied destinations, and
//! running a sandbox's egress proxy (design §6).

use std::net::SocketAddr;

use super::Engine;
use crate::error::{Error, Result};
use crate::model::Timestamp;
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
    /// It reads the active policy for each new connection, so policy
    /// changes apply without a restart.
    pub fn run_proxy(&self, name: &SandboxName, addr: SocketAddr) -> Result<()> {
        self.require_sandbox(name)?;
        self.policy(name)?;
        let store = || SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock());
        let policy = ActivePolicy {
            store: store(),
            sandbox: name.clone(),
        };
        let proxy = Proxy::new(name.clone(), Box::new(policy), Box::new(store()));
        proxy.run(addr).map_err(|source| Error::ProxyListen {
            sandbox: name.to_string(),
            addr: addr.to_string(),
            source,
        })
    }
}
