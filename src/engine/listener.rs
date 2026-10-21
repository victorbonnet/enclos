//! The runtime's own service that listens in its sandbox (ADR 0028): where
//! it listens, from enclos's records, so the sandbox's sessions may reach
//! that one port.

use std::time::{Duration, Instant};

use super::Engine;
use crate::error::Result;
use crate::lifecycle::listeners::{ephemeral_ports, one_port, tcp_listeners, tcp_listeners_at};
use crate::lifecycle::process::is_same;
use crate::model::audit::Actor;
use crate::model::sandbox::{PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord};
use crate::model::session::SessionKind;
use crate::runtime::home::stat;
use crate::runtime::{RuntimeListener, adapter};
use crate::state::StateStore;

/// How long `connect` waits for a service it started to listen.
const SERVICE_START: Duration = Duration::from_secs(60);
/// How long it waits while no session of the service is open, as when the
/// service exits at once and the service manager waits before starting it
/// again (launchd: 10 seconds).
const SERVICE_GONE: Duration = Duration::from_secs(15);
/// How often it looks.
const SERVICE_POLL: Duration = Duration::from_millis(250);

/// What `connect` did about the runtime's service before it connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWait {
    pub service: String,
    /// Whether it started the sandbox's services: false when a session of
    /// the service was open already, still starting, and was waited for.
    pub started: bool,
    /// Why the service was not listening when the wait ended, if it was not.
    pub late: Option<String>,
}

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

    /// Starts the sandbox's services when its runtime's clients need its
    /// service and no session of it is open (ADR 0028): Hermes's chat no
    /// longer starts a gateway of its own, which could not reach it, and a
    /// session reaches the service only on the port it held when the session
    /// started. A session that is open but not listening yet is a service
    /// still starting, so it is waited for, never started again, which
    /// would stop it. Nothing for a runtime whose files are gone, since its
    /// service could not run. Waits until the service listens, and gives up
    /// sooner when no session of it stays open, as when it exits at once.
    /// `None`: it listened already, or there is no such service.
    pub fn start_listener_service(
        &self,
        by: &Actor,
        name: &SandboxName,
    ) -> Result<Option<ServiceWait>> {
        let record = self.record(name)?;
        let Some(kind) = record.runtime else {
            return Ok(None);
        };
        let Some(listener) = Self::listener(&record) else {
            return Ok(None);
        };
        let home = self.layout.sandbox_home(name.as_str());
        if let Some(install) = adapter(kind).runtime_facts().install
            && !matches!(stat(&home, &install), Ok(Some(_)))
        {
            return Ok(None);
        }
        let service = listener.service.as_str();
        if service_listener(self.state.as_ref(), name, service).is_ok() {
            return Ok(None);
        }
        let start = !self.service_open(name, service)?;
        if start {
            self.start_sandbox(by, name)?;
        }
        let started = Instant::now();
        let late = loop {
            let why = match service_listener(self.state.as_ref(), name, service) {
                Ok(_) => break None,
                Err(why) => why,
            };
            let waited = started.elapsed();
            if waited >= SERVICE_START
                || waited >= SERVICE_GONE && !self.service_open(name, service)?
            {
                break Some(why);
            }
            std::thread::sleep(SERVICE_POLL);
        };
        Ok(Some(ServiceWait {
            service: service.to_owned(),
            started: start,
            late,
        }))
    }

    /// Whether a session of `service` is open with its program running.
    pub(super) fn service_open(&self, name: &SandboxName, service: &str) -> Result<bool> {
        for session in self.state.sessions(name, true)? {
            if session.kind == SessionKind::Service
                && session.service.as_deref() == Some(service)
                && is_same(&session.root)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
