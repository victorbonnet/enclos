//! The runtime's own service that listens in its sandbox (ADR 0028): where
//! it listens, from enclos's records, so the sandbox's sessions may reach
//! that one port.

use super::Engine;
use crate::lifecycle::listeners::{ephemeral_ports, one_port, tcp_listeners, tcp_listeners_at};
use crate::lifecycle::process::is_same;
use crate::model::sandbox::{PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord};
use crate::model::session::SessionKind;
use crate::runtime::{RuntimeListener, adapter};
use crate::state::StateStore;

/// The port `service` listens on now: the one TCP port at 127.0.0.1 in the
/// ephemeral range that the program its open session started holds (`enclos
/// launch` runs it; for Hermes, the gateway itself, as its wrapper and
/// `sandbox-exec` both exec), checked to be the same process before and after
/// reading its ports, so a reused pid is not taken for it, and to be the only
/// process holding 127.0.0.1 at that port, so a session reaches no other. A
/// member it started could listen too, so members are not looked at; several
/// open sessions, no port or several are refused rather than guessed among.
pub(super) fn service_listener(
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
    let ephemeral = ephemeral_ports()?;
    let held = tcp_listeners(root.pid).map_err(|e| e.to_string())?;
    let port = one_port(&held, &ephemeral)
        .map_err(|why| format!("the {service} (pid {}): {why}", root.pid))?;
    // Nothing else at 127.0.0.1 there: a socket that shares the port
    // (SO_REUSEPORT) would get the session's connections too.
    let holders = tcp_listeners_at(port).map_err(|e| e.to_string())?;
    if let Some((pid, _)) = holders.iter().find(|(pid, _)| *pid != root.pid) {
        return Err(format!(
            "pid {pid} also listens at 127.0.0.1:{port}, the {service}'s port, so a session could reach it"
        ));
    }
    // Still the same process, so the sockets were the service's.
    if !is_same(root).map_err(|e| e.to_string())? {
        return Err(format!("the {service} ended"));
    }
    Ok(port)
}

/// `port`, unless it is one of enclos's proxy ports, which a sandbox that
/// listens is kept from binding (ADR 0028): its service holding one means
/// those rules did not hold, and no session may be given another sandbox's
/// proxy.
pub(super) fn outside_proxy_range(port: u16) -> std::result::Result<u16, String> {
    match (PORT_FIRST..=PORT_LAST).contains(&port) {
        false => Ok(port),
        true => Err(format!(
            "its port {port} is one of enclos's proxy ports, {PORT_FIRST} to {PORT_LAST}, which the sandbox's policy should keep it from binding: stop the sandbox and report this"
        )),
    }
}

impl Engine {
    /// The runtime's listening service, when the sandbox's runtime has one.
    pub(super) fn listener(record: &SandboxRecord) -> Option<RuntimeListener> {
        record.runtime.and_then(|kind| adapter(kind).listener())
    }

    /// The port a session of `record` started now may reach besides its
    /// proxy: the one its runtime's service listens on (ADR 0028).
    /// `Ok(None)`: the runtime has no such service. An error: it has one,
    /// and a session started now cannot reach it, with why (not running, or
    /// its port cannot be told), for the session to say.
    pub(super) fn service_port(
        &self,
        record: &SandboxRecord,
    ) -> std::result::Result<Option<u16>, String> {
        let Some(listener) = Self::listener(record) else {
            return Ok(None);
        };
        let service = listener.service.as_str();
        service_listener(self.state.as_ref(), &record.name, service)
            .and_then(outside_proxy_range)
            .map(Some)
            .map_err(|why| {
                format!(
                    "this session cannot reach the {service} ({why}); open it again once the {service} listens: `enclos sandbox start {}` starts it",
                    record.name
                )
            })
    }
}
