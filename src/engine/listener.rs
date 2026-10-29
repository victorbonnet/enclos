//! The runtime's own service that listens in its sandbox (ADR 0028): where
//! it listens, from enclos's records, so the sandbox's sessions may reach
//! that one port; and starting it before `connect`, since a session reaches
//! it only on the port it held when the session started.

use std::fmt;
use std::fs::{OpenOptions, TryLockError};
use std::time::{Duration, Instant};

use super::Engine;
use super::service::Unit;
use crate::error::Result;
use crate::layout::LayoutError;
use crate::lifecycle::listeners::{
    NotOnePort, ephemeral_ports, one_port, tcp_listeners, tcp_listeners_at,
};
use crate::lifecycle::process::is_same;
use crate::model::audit::Actor;
use crate::model::sandbox::{PORT_FIRST, PORT_LAST, SandboxName, SandboxRecord};
use crate::model::session::{ProcessRef, SessionKind};
use crate::runtime::home::stat;
use crate::runtime::{RuntimeListener, adapter};
use crate::state::StateStore;

/// The limits of `connect`'s wait for the service to listen.
#[derive(Debug, Clone, Copy)]
pub(super) struct ServiceTimes {
    /// How long it waits at most.
    pub(super) start: Duration,
    /// How long it waits while no session of the service is open, as when
    /// the service exits at once and the service manager waits before
    /// starting it again (launchd: 10 seconds).
    pub(super) gone: Duration,
    /// How often it looks.
    pub(super) poll: Duration,
}

impl ServiceTimes {
    const REAL: ServiceTimes = ServiceTimes {
        start: Duration::from_secs(60),
        gone: Duration::from_secs(15),
        poll: Duration::from_millis(250),
    };
}

/// Why a service has no port a session can be given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NoPort {
    /// No session of it runs.
    NotRunning(String),
    /// Its session runs and holds no port yet, as one still starting.
    NotYet(String),
    /// What waiting does not fix: several sessions or ports, a port another
    /// process shares, a look that failed.
    Refused(String),
}

impl fmt::Display for NoPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoPort::NotRunning(why) | NoPort::NotYet(why) | NoPort::Refused(why) => {
                f.write_str(why)
            }
        }
    }
}

fn refused(e: impl fmt::Display) -> NoPort {
    NoPort::Refused(e.to_string())
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
) -> std::result::Result<u16, NoPort> {
    let root = running_session(store, sandbox, service)?;
    let ephemeral = ephemeral_ports().map_err(refused)?;
    let held = tcp_listeners(root.pid).map_err(refused)?;
    let port = one_port(&held, &ephemeral).map_err(|e| {
        let why = format!("the {service} (pid {}): {e}", root.pid);
        match e {
            NotOnePort::None(_) => NoPort::NotYet(why),
            NotOnePort::Several(_) => NoPort::Refused(why),
        }
    })?;
    // Nothing else at 127.0.0.1 there: a socket that shares the port
    // (SO_REUSEPORT) would get the session's connections too.
    let holders = tcp_listeners_at(port).map_err(refused)?;
    if let Some((pid, _)) = holders.iter().find(|(pid, _)| *pid != root.pid) {
        return Err(NoPort::Refused(format!(
            "pid {pid} also listens at 127.0.0.1:{port}, the {service}'s port, so a session could reach it"
        )));
    }
    // Still the same process, so the sockets were the service's.
    if !is_same(&root).map_err(refused)? {
        return Err(NoPort::NotRunning(format!("the {service} ended")));
    }
    Ok(port)
}

/// The root of the one open session of `service` whose program still runs.
fn running_session(
    store: &dyn StateStore,
    sandbox: &SandboxName,
    service: &str,
) -> std::result::Result<ProcessRef, NoPort> {
    let sessions = store.sessions(sandbox, true).map_err(refused)?;
    let mut running = Vec::new();
    for session in sessions
        .into_iter()
        .filter(|s| s.kind == SessionKind::Service && s.service.as_deref() == Some(service))
    {
        if is_same(&session.root).map_err(refused)? {
            running.push(session.root);
        }
    }
    match running.len() {
        0 => Err(NoPort::NotRunning(format!("the {service} is not running"))),
        1 => Ok(running.remove(0)),
        n => Err(NoPort::Refused(format!(
            "{n} {service} sessions are running, so which is the service cannot be told"
        ))),
    }
}

/// `port`, unless it is one of enclos's proxy ports, which a sandbox that
/// listens is kept from binding (ADR 0028): its service holding one means
/// those rules did not hold, and no session may be given another sandbox's
/// proxy.
pub(super) fn outside_proxy_range(port: u16) -> std::result::Result<u16, NoPort> {
    match (PORT_FIRST..=PORT_LAST).contains(&port) {
        false => Ok(port),
        true => Err(NoPort::Refused(format!(
            "its port {port} is one of enclos's proxy ports, {PORT_FIRST} to {PORT_LAST}, which the sandbox's policy should keep it from binding: stop the sandbox and report this"
        ))),
    }
}

/// What `connect` does about the runtime's service before its session
/// starts, decided the same way for `--dry-run` and for the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConnectStep {
    /// Nothing: the runtime has no such service, its files are gone (its
    /// service could not run), or the service listens.
    Nothing,
    /// Whether the runtime's files are there cannot be told: nothing is
    /// started, and this says why.
    Unreadable(String),
    /// A session of the service is open, or the service is installed and
    /// the service manager starts it again: wait for it to listen.
    /// Installing the services again would stop the proxy that open
    /// sessions use, and a service still starting.
    Wait,
    /// The service is not installed, as when the sandbox was started before
    /// its runtime was installed: start the sandbox's services, then wait.
    Start,
}

/// What `connect` did about the runtime's service before it connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWait {
    pub service: String,
    /// Whether it started the sandbox's services: false when it only
    /// waited (the service was installed, or a session of it was open),
    /// when the start failed, or when whether the runtime is there could
    /// not be told.
    pub started: bool,
    /// Why the service was not listening when the wait ended, if it was not:
    /// it did not listen in time, its port cannot be told, its services
    /// could not start, or the runtime's files cannot be read.
    pub late: Option<String>,
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

    /// What `connect` does about `record`'s runtime service, with the
    /// service, when its runtime has one.
    pub(super) fn connect_step(
        &self,
        record: &SandboxRecord,
    ) -> Result<Option<(RuntimeListener, ConnectStep)>> {
        let (Some(kind), Some(listener)) = (record.runtime, Self::listener(record)) else {
            return Ok(None);
        };
        let name = &record.name;
        if let Some(install) = adapter(kind).runtime_facts().install {
            match stat(&self.layout.sandbox_home(name.as_str()), &install) {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(Some((listener, ConnectStep::Nothing))),
                Err(why) => {
                    let why = format!("whether {kind} is installed cannot be told: {why}");
                    return Ok(Some((listener, ConnectStep::Unreadable(why))));
                }
            }
        }
        let step = match service_listener(self.state.as_ref(), name, listener.service.as_str()) {
            Ok(_) => ConnectStep::Nothing,
            Err(NoPort::NotRunning(_))
                if !self.unit_installed(name, Unit::Runtime(listener.service))? =>
            {
                ConnectStep::Start
            }
            Err(_) => ConnectStep::Wait,
        };
        Ok(Some((listener, step)))
    }

    /// Makes sure the runtime's service listens before `connect` or `exec`
    /// starts its session (ADR 0028): Hermes's chat no longer starts a gateway of its
    /// own, which could not reach it, and a session reaches the service only
    /// on the port it held when the session started. Starts the sandbox's
    /// services when its service is not installed and does not run, which
    /// replaces a proxy service already installed, then waits for the service
    /// to listen, saying what it does through `say` before it waits. It
    /// gives up sooner while no session of the service is open, as when it
    /// exits at once, and at once for what waiting does not fix (several
    /// ports, a port another process shares). A start that fails ends it
    /// too: the session goes ahead either way, with why in `late`. One
    /// session of a sandbox at a time decides and waits, so two never
    /// start its services at once. `None`: there was nothing to do.
    pub fn start_listener_service(
        &self,
        by: &Actor,
        name: &SandboxName,
        say: &mut dyn FnMut(String),
    ) -> Result<Option<ServiceWait>> {
        self.start_listener_service_in(by, name, say, ServiceTimes::REAL)
    }

    pub(super) fn start_listener_service_in(
        &self,
        by: &Actor,
        name: &SandboxName,
        say: &mut dyn FnMut(String),
        times: ServiceTimes,
    ) -> Result<Option<ServiceWait>> {
        let _turn = self.connect_turn(name, say)?;
        let record = self.record(name)?;
        let Some((listener, step)) = self.connect_step(&record)? else {
            return Ok(None);
        };
        let service = listener.service.as_str();
        let done = |started, late| {
            Ok(Some(ServiceWait {
                service: service.to_owned(),
                started,
                late,
            }))
        };
        let started = match step {
            ConnectStep::Nothing => return Ok(None),
            ConnectStep::Unreadable(why) => return done(false, Some(why)),
            ConnectStep::Wait => false,
            ConnectStep::Start => {
                // A running proxy, one an earlier `connect` started or the
                // proxy service, gives way to the proxy service installed
                // now, on the same port.
                let cut = match self.proxy_runs(name)? {
                    true => {
                        " Its proxy starts again as a service, so the connections of its open sessions are cut."
                    }
                    false => "",
                };
                say(format!(
                    "starting the services of sandbox {name}, since its runtime's clients need its {service}. They start again at each login until `enclos sandbox stop {name}`.{cut}"
                ));
                // A start that fails after removing the services it replaces
                // leaves none: said when the proxy service was among them.
                let had_proxy = self.unit_installed(name, Unit::Proxy)?;
                if let Err(e) = self.start_sandbox(by, name) {
                    let gone = had_proxy && !self.unit_installed(name, Unit::Proxy).unwrap_or(true);
                    let lost = match gone {
                        true => format!(
                            "; its proxy service was removed with them and no longer starts at login, until `enclos sandbox start {name}`"
                        ),
                        false => String::new(),
                    };
                    return done(
                        false,
                        Some(format!("its services could not start: {e}{lost}")),
                    );
                }
                true
            }
        };
        say(format!(
            "waiting for the {service} of sandbox {name} to listen…"
        ));
        let begun = Instant::now();
        let mut seen: Option<ProcessRef> = None;
        let mut restarted = false;
        let late = loop {
            let why = match service_listener(self.state.as_ref(), name, service) {
                Ok(_) => break None,
                Err(NoPort::Refused(why)) => break Some(why),
                Err(NoPort::NotRunning(why) | NoPort::NotYet(why)) => why,
            };
            // Another session of it than the one seen before: it exited and
            // was started again.
            let open = match running_session(self.state.as_ref(), name, service) {
                Ok(root) => {
                    restarted |= seen.as_ref().is_some_and(|s| *s != root);
                    seen = Some(root);
                    true
                }
                Err(_) => false,
            };
            let waited = begun.elapsed();
            if waited >= times.start || (waited >= times.gone && !open) {
                break Some(match restarted {
                    true => format!("{why}; it exited and was started again while enclos waited"),
                    false => why,
                });
            }
            std::thread::sleep(times.poll);
        };
        done(started, late)
    }

    /// The sandbox's `connect` turn: held while one `connect` decides
    /// whether to start the services and waits, so another waits for it
    /// rather than starting them again. A file lock, released when the
    /// returned file is dropped or the process ends.
    fn connect_turn(
        &self,
        name: &SandboxName,
        say: &mut dyn FnMut(String),
    ) -> Result<std::fs::File> {
        let dir = self.layout.run_dir();
        let path = dir.join(format!("{name}.connect.lock"));
        let io = |source| LayoutError::Io {
            path: path.clone(),
            source,
        };
        std::fs::create_dir_all(&dir).map_err(io)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                say(format!(
                    "waiting for another `enclos connect {name}`, which is starting its runtime's service…"
                ));
                file.lock().map_err(io)?;
            }
            Err(TryLockError::Error(e)) => return Err(io(e).into()),
        }
        Ok(file)
    }
}
