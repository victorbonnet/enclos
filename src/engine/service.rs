//! A sandbox's background services (design §4, ADRs 0002, 0021): its proxy
//! and the services its runtime declares, run by the host's service manager
//! while the user is logged in. `sandbox start` installs them, so they come
//! back at each login; `sandbox stop` removes them.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

use super::Engine;
use super::session::{END_WAIT, SessionEnd, abandon};
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::process::{group_of, is_same, reference, reference_of_child};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::policy::sha256_hex;
use crate::runtime::{RuntimeService, ServiceName, adapter};
use crate::service::{LABEL_PREFIX, ServiceLabel, ServiceStatus, ServiceUnit};

/// One of a sandbox's services: its proxy, or one its runtime declares,
/// by the name the runtime gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Proxy,
    Runtime(ServiceName),
}

impl Unit {
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Proxy => "proxy",
            Unit::Runtime(name) => name.as_str(),
        }
    }
}

/// How long `launch` and `connect` wait for the sandbox's proxy to record
/// itself as running (`proxy run --record`).
pub const PROXY_WAIT: Duration = Duration::from_secs(15);
/// How long a runtime service's members have to exit after TERM, and again
/// after KILL, when its `enclos launch` is told to end.
pub const STOP_GRACE: Duration = Duration::from_secs(30);
/// How long the service manager waits for `launch` after telling it to end,
/// before killing it: TERM, `STOP_GRACE`, KILL, `STOP_GRACE`, then
/// recording the end, which waits for the state lock up to `END_WAIT`.
pub const STOP_TIMEOUT: Duration =
    Duration::from_secs(2 * STOP_GRACE.as_secs() + END_WAIT.as_secs() + 10);

impl Engine {
    /// The start of every label of the sandbox's services. Labels are
    /// shared by every enclos install of the user (`ENCLOS_HOME`), and a
    /// sandbox name is unique only within one, so the label names the
    /// install too: the first 8 hex digits of the SHA-256 of its data
    /// folder, with links and `.` resolved, so that every spelling of the
    /// folder names the same services.
    fn label_prefix(&self, name: &SandboxName) -> Result<String> {
        let data = self.layout.data();
        let data = match std::fs::canonicalize(data) {
            Ok(data) => data,
            // Missing, the folder has no sandboxes, so no services either.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => data.to_owned(),
            Err(source) => {
                return Err(LayoutError::Io {
                    path: data.to_owned(),
                    source,
                }
                .into());
            }
        };
        let install = &sha256_hex(data.as_os_str().as_bytes())[..8];
        Ok(format!("{LABEL_PREFIX}{install}.{name}."))
    }

    /// The service manager's label of one of the sandbox's services.
    pub fn label(&self, name: &SandboxName, unit: Unit) -> Result<ServiceLabel> {
        let text = format!("{}{}", self.label_prefix(name)?, unit.as_str());
        Ok(ServiceLabel::parse(&text).expect("a label is built from short names"))
    }

    /// The services `start_sandbox` installs for a runtime declaring
    /// `services`: the proxy, then those, as declared.
    fn units_for(services: &[RuntimeService]) -> Vec<Unit> {
        std::iter::once(Unit::Proxy)
            .chain(services.iter().map(|s| Unit::Runtime(s.name)))
            .collect()
    }

    fn units(record: &SandboxRecord) -> Vec<Unit> {
        let services = record
            .runtime
            .map(|kind| adapter(kind).services())
            .unwrap_or_default();
        Self::units_for(&services)
    }

    /// The labels `start_sandbox` installs.
    pub fn service_labels(&self, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let record = self.record(name)?;
        Self::units(&record)
            .into_iter()
            .map(|u| self.label(name, u))
            .collect()
    }

    /// The labels of the sandbox installed now, the proxy last: those this
    /// enclos would install, and any other under the sandbox's prefix, such
    /// as one a runtime no longer declares.
    fn installed_labels(&self, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let mut labels = self.services.installed(&self.label_prefix(name)?)?;
        let proxy = self.label(name, Unit::Proxy)?;
        labels.sort_by_key(|l| (*l == proxy, l.clone()));
        Ok(labels)
    }

    fn logs_dir(&self, name: &SandboxName) -> PathBuf {
        self.layout.sandbox_dir(name.as_str()).join("logs")
    }

    fn log_file(&self, name: &SandboxName, unit: Unit) -> PathBuf {
        self.logs_dir(name).join(format!("{}.log", unit.as_str()))
    }

    fn record(&self, name: &SandboxName) -> Result<SandboxRecord> {
        self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })
    }

    /// Installs the sandbox's proxy and its runtime's services, replacing
    /// those it has already. If one cannot be installed, none stays
    /// installed and the sandbox is marked failed. The services start on
    /// their own; `proxy_started` says when the proxy has.
    pub fn start_sandbox(&self, by: &Actor, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        self.require_sandbox(name)?;
        // Before anything is stopped: an unavailable manager (no login
        // session, another system) would leave the sandbox with nothing.
        self.services.available()?;
        // A damaged audit log would refuse the audited install after the
        // removal, leaving the sandbox with nothing.
        self.audit.check()?;
        // Outside the lock, here and on failure: a runtime service told to
        // end stops its runtime and records its end, which needs the lock.
        self.stop_services(name)?;
        self.install_services(by, name)
            .map_err(|error| match self.stop_services(name) {
                Ok(_) => error,
                Err(left) => Error::CleanupFailed {
                    error: Box::new(error),
                    left: left.to_string(),
                },
            })
    }

    fn install_services(&self, by: &Actor, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let summary = |labels: &Vec<ServiceLabel>| {
            labels
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        self.write(
            by,
            "sandbox start",
            Some(name.to_string()),
            summary,
            |lock| {
                let mut record = self.record(name)?;
                let installed = (|| -> Result<Vec<ServiceLabel>> {
                    self.backend_of(name)?;
                    let exe = self.exe.clone().ok_or_else(|| Error::Session {
                        what: "cannot find the enclos program".into(),
                    })?;
                    let logs = self.logs_dir(name);
                    std::fs::create_dir_all(&logs)
                        .map_err(|source| LayoutError::Io { path: logs, source })?;
                    // A proxy `connect` started would hold the port the
                    // service needs, and what a runtime service left running
                    // would run beside the new one.
                    self.stop_sessions(lock, name, &[SessionKind::Proxy, SessionKind::Service])?;
                    let units = Self::units(&record)
                        .into_iter()
                        .map(|unit| {
                            Ok(ServiceUnit {
                                label: self.label(name, unit)?,
                                program: exe.clone(),
                                args: match unit {
                                    Unit::Proxy => vec![
                                        "proxy".into(),
                                        "run".into(),
                                        name.to_string().into(),
                                        "--record".into(),
                                        "--listen".into(),
                                        format!("127.0.0.1:{}", record.proxy_port).into(),
                                    ],
                                    Unit::Runtime(service) => vec![
                                        "launch".into(),
                                        name.to_string().into(),
                                        service.as_str().into(),
                                    ],
                                },
                                log: self.log_file(name, unit),
                                env: self.layout.env(),
                                stop_timeout: STOP_TIMEOUT,
                            })
                        })
                        .collect::<Result<Vec<ServiceUnit>>>()?;
                    for unit in &units {
                        self.services.start(unit)?;
                    }
                    Ok(units.into_iter().map(|u| u.label).collect())
                })();
                record.state = match &installed {
                    Ok(_) => SandboxState::Running,
                    Err(e) => SandboxState::Failed {
                        reason: format!("start failed: {e}"),
                    },
                };
                self.state.put(lock, &record)?;
                installed
            },
        )
    }

    /// Removes every service of the sandbox installed now, the proxy last,
    /// and returns what it removed; `stop_sandbox` calls this first.
    pub(super) fn stop_services(&self, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let labels = self.installed_labels(name)?;
        for label in &labels {
            self.services.stop(label)?;
        }
        Ok(labels)
    }

    /// Whether the sandbox has services installed, running or not.
    pub(super) fn has_services(&self, name: &SandboxName) -> Result<bool> {
        Ok(!self.installed_labels(name)?.is_empty())
    }

    /// Each installed service of the sandbox and whether it runs.
    pub fn service_status(&self, name: &SandboxName) -> Result<Vec<(ServiceLabel, ServiceStatus)>> {
        self.installed_labels(name)?
            .into_iter()
            .map(|l| {
                let status = self.services.status(&l)?;
                Ok((l, status))
            })
            .collect()
    }

    /// Whether the sandbox's proxy records itself as running within `wait`:
    /// a service manager starts it after `start_sandbox` returns, and a
    /// proxy that cannot take its port never does (`enclos logs` says why).
    pub fn proxy_started(&self, name: &SandboxName, wait: Duration) -> Result<bool> {
        self.require_sandbox(name)?;
        let start = Instant::now();
        loop {
            if self.proxy_runs(name)? {
                return Ok(true);
            }
            if start.elapsed() >= wait {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A runtime service's process: runs the command the sandbox's runtime
    /// declares under `service` in the sandbox, in a process group of its
    /// own, recorded as a session. Told to end (TERM, as the service manager
    /// does, INT or HUP), it stops the session's members and records the
    /// end.
    pub fn launch(&self, by: &Actor, name: &SandboxName, service: &str) -> Result<SessionEnd> {
        let ended = Arc::new(AtomicBool::new(false));
        let _ending = EndOn::new(&ended)?;
        self.launch_until(by, name, service, &ended)
    }

    /// `launch`, ending once `ended` is set.
    pub(super) fn launch_until(
        &self,
        by: &Actor,
        name: &SandboxName,
        service: &str,
        ended: &AtomicBool,
    ) -> Result<SessionEnd> {
        let kind = self.runtime_of(name)?;
        let command = adapter(kind)
            .services()
            .into_iter()
            .find(|s| s.name.as_str() == service)
            .ok_or_else(|| Error::Session {
                what: format!("{kind} has no background service named {service}"),
            })?
            .command
            .into_words();
        let (program, args) = command.split_first().ok_or_else(|| Error::Session {
            what: format!("{kind} declares the {service} service with no command"),
        })?;
        let record = self.record(name)?;
        // The sandbox's own proxy, not whatever listens on its port: a proxy
        // records itself only once it holds the port, so a recorded proxy
        // session whose process still runs is the proof (`proxy run --record`).
        let start = Instant::now();
        while !self.proxy_runs(name)? {
            if ended.load(Ordering::Relaxed) {
                return Err(Error::Session {
                    what: format!("told to end before the {service} service of {name} started"),
                });
            }
            if start.elapsed() > PROXY_WAIT {
                return Err(Error::Session {
                    what: format!(
                        "the proxy of sandbox {name} did not start on port {}; see `enclos logs {name}`",
                        record.proxy_port
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let summary = |(session, _): &(SessionRecord, _)| format!("session {}", session.id);
        let (session, mut child) =
            self.write(by, "launch", Some(name.to_string()), summary, |lock| {
                // A service session whose `launch` was killed before it
                // recorded its end, at logout or by the service manager's
                // timeout: its process is gone, so it ends here.
                self.end_dead_sessions(lock, name, SessionKind::Service)?;
                let compiled = self.compile_policy(name, record.proxy_port)?;
                let (version, snapshot) = self.active_policy(name)?;
                let launch = Launch {
                    program: program.clone(),
                    args: args.to_vec(),
                    env: Vec::new(),
                };
                let ctx = self.sandbox_context(name, record.proxy_port);
                let mut wrapped = self.backend_of(name)?.wrap(&compiled, &ctx, &launch);
                let child = wrapped
                    .process_group(0)
                    .spawn()
                    .map_err(|e| Error::Session {
                        what: format!("could not start the {kind} {service} service: {e}"),
                    })?;
                let recorded = (|| -> Result<SessionRecord> {
                    let mut session = SessionRecord {
                        id: SessionId(0),
                        sandbox: name.clone(),
                        kind: SessionKind::Service,
                        version: version.version,
                        snapshot: snapshot.id,
                        compiled: Some(compiled.display().to_string()),
                        // In a group made for it, which it leads.
                        pgid: Some(child.id()),
                        root: reference_of_child(&child)?,
                        tracked: Vec::new(),
                        started_at: now(),
                        ended_at: None,
                    };
                    session.id = self.state.put_session(lock, &session)?;
                    Ok(session)
                })();
                match recorded {
                    Ok(session) => Ok((session, child)),
                    Err(e) => Err(abandon(child, e, "the service")),
                }
            })?;
        // As for `connect`, the members the service starts are recorded.
        // Unlike `connect`, what it leaves running is stopped: under a
        // service manager the service is its program, which the manager
        // starts again, and what the last run left would run beside it.
        let mut waited = self.wait_session(&session, &mut child, Some(ended))?;
        self.stop_left(&session, &mut waited);
        self.finish_session(by, "service end", &session, waited)
    }

    /// Ends the sandbox's sessions of `kind` whose root process is gone.
    pub(super) fn end_dead_sessions(
        &self,
        lock: &crate::state::StateLock,
        name: &SandboxName,
        kind: SessionKind,
    ) -> Result<()> {
        for session in self.state.sessions(name, true)? {
            if session.kind == kind && !is_same(&session.root)? {
                self.state.end_session(lock, session.id)?;
            }
        }
        Ok(())
    }

    /// Records this process as the sandbox's proxy: `proxy run --record`
    /// calls it once it holds the port, so `connect` and `launch` know it
    /// runs. A recorded proxy whose process is gone ends here: at logout or
    /// a crash, a proxy service dies with its session open.
    pub(super) fn record_proxy(&self, by: &Actor, name: &SandboxName) -> Result<SessionId> {
        let me = std::process::id();
        self.write(
            by,
            "proxy start",
            Some(name.to_string()),
            |id| format!("session {id}"),
            |lock| {
                self.end_dead_sessions(lock, name, SessionKind::Proxy)?;
                let (version, snapshot) = self.active_policy(name)?;
                let session = SessionRecord {
                    id: SessionId(0),
                    sandbox: name.clone(),
                    kind: SessionKind::Proxy,
                    version: version.version,
                    snapshot: snapshot.id,
                    compiled: None,
                    root: reference(me)?.ok_or_else(|| Error::Session {
                        what: "cannot read this process's start time".into(),
                    })?,
                    // Its group only when it leads it, as under a service
                    // manager: otherwise the group is its caller's.
                    pgid: (group_of(me)? == Some(me)).then_some(me),
                    tracked: Vec::new(),
                    started_at: now(),
                    ended_at: None,
                };
                Ok(self.state.put_session(lock, &session)?)
            },
        )
    }

    /// The service logs of a sandbox, the proxy's first.
    pub fn log_files(&self, name: &SandboxName) -> Result<Vec<PathBuf>> {
        self.require_sandbox(name)?;
        let logs = self.logs_dir(name);
        let entries = match std::fs::read_dir(&logs) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(LayoutError::Io { path: logs, source }.into()),
        };
        let proxy = self.log_file(name, Unit::Proxy);
        let mut files = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|source| LayoutError::Io {
                    path: logs.clone(),
                    source,
                })?
                .path();
            if path.extension().is_some_and(|x| x == "log") {
                files.push(path);
            }
        }
        files.sort_by_key(|p| (*p != proxy, p.clone()));
        Ok(files)
    }
}

/// Sets `ended` on TERM, INT and HUP while it lives, instead of ending this
/// process: `launch` outlives them to stop the runtime, which runs in a
/// group of its own that the service manager does not signal, and to
/// record its end.
struct EndOn(Vec<signal_hook::SigId>);

impl EndOn {
    fn new(ended: &Arc<AtomicBool>) -> Result<Self> {
        // The guard first, so what is registered is unregistered even when a
        // later registration fails.
        let mut guard = EndOn(Vec::new());
        for signal in [SIGTERM, SIGINT, SIGHUP] {
            let id = signal_hook::flag::register(signal, Arc::clone(ended)).map_err(|e| {
                Error::Session {
                    what: format!("cannot handle signal {signal}: {e}"),
                }
            })?;
            guard.0.push(id);
        }
        Ok(guard)
    }
}

impl Drop for EndOn {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// Tests that raise TERM at this process take this first: the flag of every
/// `EndOn` registered then would be set.
#[cfg(test)]
pub(crate) static TERM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_units_are_the_proxy_then_each_declared_service() {
        use crate::runtime::SandboxCommand;
        let service = |name| RuntimeService {
            name: ServiceName::new(name),
            command: SandboxCommand::from_words(&["x"]),
        };
        assert_eq!(Engine::units_for(&[]), [Unit::Proxy]);
        assert_eq!(
            Engine::units_for(&[service("mail"), service("gateway")]),
            [
                Unit::Proxy,
                Unit::Runtime(ServiceName::new("mail")),
                Unit::Runtime(ServiceName::new("gateway")),
            ]
        );
    }

    #[test]
    fn the_stop_timeout_covers_both_grace_periods_and_recording_the_end() {
        assert!(STOP_TIMEOUT > 2 * STOP_GRACE + END_WAIT);
    }

    #[test]
    fn end_on_sets_the_flag_on_term_and_the_process_lives() {
        let _term = TERM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ended = Arc::new(AtomicBool::new(false));
        let _ending = EndOn::new(&ended).unwrap();
        signal_hook::low_level::raise(SIGTERM).unwrap();
        let start = Instant::now();
        while !ended.load(Ordering::Relaxed) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the flag was not set"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
