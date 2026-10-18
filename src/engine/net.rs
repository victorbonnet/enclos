//! The engine's network calls: the network log, denied destinations, and
//! running a sandbox's egress proxy (design §6).

use super::Engine;
use crate::error::{Error, Result};
use crate::model::Timestamp;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::sandbox::SandboxName;
use crate::proxy::{ActivePolicy, Listener, Proxy};
use crate::state::sqlite::SqliteStateStore;

impl Engine {
    /// The sandbox's connections, oldest first, optionally for one profile
    /// and from `since` on.
    pub fn net_log(
        &self,
        name: &SandboxName,
        profile: Option<&str>,
        since: Option<Timestamp>,
    ) -> Result<Vec<NetEvent>> {
        self.require_sandbox(name)?;
        Ok(self.state.events(name, profile, since)?)
    }

    /// Each destination the sandbox was refused, most recent first.
    pub fn net_denied(&self, name: &SandboxName) -> Result<Vec<DeniedDestination>> {
        self.require_sandbox(name)?;
        Ok(self.state.denied(name)?)
    }

    /// Runs the sandbox's egress proxy on `listeners` until the process ends.
    /// It reads the active policy for each new connection, so policy
    /// changes apply without a restart.
    pub fn run_proxy(&self, name: &SandboxName, listeners: &[Listener]) -> Result<()> {
        self.require_sandbox(name)?;
        self.policy(name)?;
        let store = || SqliteStateStore::new(self.layout.state_db(), self.layout.state_lock());
        let policy = ActivePolicy {
            store: store(),
            sandbox: name.clone(),
        };
        let proxy = Proxy::new(name.clone(), Box::new(policy), Box::new(store()));
        proxy.run(listeners).map_err(|source| Error::ProxyListen {
            sandbox: name.to_string(),
            addr: listeners
                .iter()
                .map(|l| l.addr.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            source,
        })
    }
}
