//! The runtime's own service that listens in its sandbox (ADR 0028): where
//! it listens, from enclos's records, so the sandbox's sessions may reach
//! that one port.

use super::Engine;
use crate::lifecycle::listeners::{ephemeral_ports, one_port, tcp_listeners};
use crate::lifecycle::process::is_same;
use crate::model::sandbox::{PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord};
use crate::model::session::SessionKind;
use crate::runtime::{RuntimeListener, adapter};
use crate::state::StateStore;

/// The port `service` listens on now: the one TCP port on 127.0.0.1 in the
/// ephemeral range that the program its open session started holds (`enclos
/// launch` runs it; for Hermes, the gateway itself, as its wrapper and
/// `sandbox-exec` both exec), checked to be the same process before and after
/// reading its ports, so a reused pid is not taken for it. A child it started
/// could listen too, so members are not looked at; two open sessions, no port
/// or several are refused rather than guessed among.
pub(crate) fn service_listener(
    store: &dyn StateStore,
    sandbox: &SandboxName,
    service: &str,
) -> std::result::Result<u16, String> {
    let sessions = store.sessions(sandbox, true).map_err(|e| e.to_string())?;
    let mut running = Vec::new();
    for session in sessions
        .iter()
        .filter(|s| s.kind == SessionKind::Service && s.service.as_deref() == Some(service))
    {
        if is_same(&session.root).map_err(|e| e.to_string())? {
            running.push(&session.root);
        }
    }
    let root = match running.as_slice() {
        [] => return Err(format!("the {service} is not running")),
        [root] => *root,
        several => {
            return Err(format!(
                "{} {service} sessions are running, so which is the service cannot be told",
                several.len()
            ));
        }
    };
    let held = tcp_listeners(root.pid).map_err(|e| e.to_string())?;
    // Still the same process, so the sockets were the service's.
    if !is_same(root).map_err(|e| e.to_string())? {
        return Err(format!("the {service} ended"));
    }
    one_port(&held, &ephemeral_ports())
        .map_err(|why| format!("the {service} (pid {}): {why}", root.pid))
}

impl Engine {
    /// The runtime's listening service, when the sandbox's runtime has one.
    pub(super) fn listener(record: &SandboxRecord) -> Option<RuntimeListener> {
        record.runtime.and_then(|kind| adapter(kind).listener())
    }

    /// The port a session of `record` started now may reach besides its
    /// proxy: the one its runtime's service listens on (ADR 0028). None when
    /// the runtime has no such service, or it does not listen. Never a
    /// proxy port, which a sandbox that listens cannot bind anyway.
    pub(super) fn service_port(&self, record: &SandboxRecord) -> Option<u16> {
        let listener = Self::listener(record)?;
        let port =
            service_listener(self.state.as_ref(), &record.name, listener.service.as_str()).ok()?;
        (!(PORT_FIRST..=PORT_LAST).contains(&port)).then_some(port)
    }
}
