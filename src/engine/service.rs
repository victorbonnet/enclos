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
use super::session::{SessionEnd, abandon};
use crate::backend::Launch;
use crate::error::{Error, Result};
use crate::lifecycle::process::{group_of, reference, reference_of_child};
use crate::model::audit::Actor;
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::policy::sha256_hex;
use crate::runtime::adapter;
use crate::service::{ServiceError, ServiceStatus, ServiceUnit};

/// One of a sandbox's services: its proxy, or one its runtime declares,
/// by the name the runtime gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Proxy,
    Runtime(&'static str),
}

impl Unit {
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Proxy => "proxy",
            Unit::Runtime(name) => name,
        }
    }
}

/// How long the gateway waits for the proxy service to listen.
const PROXY_WAIT: Duration = Duration::from_secs(15);
/// How long a runtime service's members have to exit after TERM, and again
/// after KILL, when its `enclos launch` is told to end. Its job file gives
/// launchd's wait for `launch` itself room for both.
pub const STOP_GRACE: Duration = Duration::from_secs(30);

impl Engine {
    /// The start of every label of the sandbox's services. Labels are
    /// shared by every enclos install of the user (`ENCLOS_HOME`), and a
    /// sandbox name is unique only within one, so the label names the
    /// install too: the first 8 hex digits of the SHA-256 of its data
    /// folder, with links and `.` resolved, so that every spelling of the
    /// folder names the same services.
    fn label_prefix(&self, name: &SandboxName) -> String {
        let data = self.layout.data();
        // Missing, the folder has no sandboxes, so no services either.
        let data = std::fs::canonicalize(data).unwrap_or_else(|_| data.to_owned());
        let install = &sha256_hex(data.as_os_str().as_bytes())[..8];
        format!("enclos.{install}.{name}.")
    }

    /// The service manager's label of one of the sandbox's services.
    pub fn label(&self, name: &SandboxName, unit: Unit) -> String {
        format!("{}{}", self.label_prefix(name), unit.as_str())
    }

    /// The services `start_sandbox` installs: the proxy, then those of the
    /// sandbox's runtime.
    fn units(record: &SandboxRecord) -> Vec<Unit> {
        let runtime = record.runtime.map(|kind| adapter(kind).services());
        std::iter::once(Unit::Proxy)
            .chain(runtime.into_iter().flatten().map(|s| Unit::Runtime(s.name)))
            .collect()
    }

    /// The labels `start_sandbox` installs.
    pub fn service_labels(&self, name: &SandboxName) -> Result<Vec<String>> {
        let record = self.record(name)?;
        Ok(Self::units(&record)
            .into_iter()
            .map(|u| self.label(name, u))
            .collect())
    }

    /// The labels of the sandbox installed now, the proxy last: those this
    /// enclos would install, and any other under the sandbox's prefix, such
    /// as one a runtime no longer declares.
    fn installed_labels(&self, name: &SandboxName) -> Result<Vec<String>> {
        let mut labels = self
            .services
            .installed(&self.label_prefix(name))
            .map_err(service_error)?;
        let proxy = self.label(name, Unit::Proxy);
        labels.sort_by_key(|l| *l == proxy);
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

    /// Starts the sandbox's proxy and its runtime's services, replacing
    /// those it has already. If one cannot start, none stays installed.
    pub fn start_sandbox(&self, by: &Actor, name: &SandboxName) -> Result<Vec<String>> {
        self.require_sandbox(name)?;
        // Outside the lock, here and on failure: a runtime service told to
        // end stops its runtime and records its end, which needs the lock.
        self.stop_services(name)?;
        self.install_services(by, name)
            .map_err(|error| match self.stop_services(name) {
                Ok(()) => error,
                Err(left) => Error::CleanupFailed {
                    error: Box::new(error),
                    left: left.to_string(),
                },
            })
    }

    fn install_services(&self, by: &Actor, name: &SandboxName) -> Result<Vec<String>> {
        let summary = |labels: &Vec<String>| labels.join(", ");
        self.write(
            by,
            "sandbox start",
            Some(name.to_string()),
            summary,
            |lock| {
                let mut record = self.record(name)?;
                self.backend_of(name)?;
                let exe = self.exe.clone().ok_or_else(|| Error::Session {
                    what: "cannot find the enclos program".into(),
                })?;
                std::fs::create_dir_all(self.logs_dir(name)).ok();
                // A proxy `connect` started would hold the ports the service
                // needs, and what a runtime service left running would run
                // beside the new one.
                self.stop_sessions(lock, name, &[SessionKind::Proxy, SessionKind::Service])?;

                let units: Vec<ServiceUnit> = Self::units(&record)
                    .into_iter()
                    .map(|unit| ServiceUnit {
                        label: self.label(name, unit),
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
                            Unit::Runtime(service) => {
                                vec!["launch".into(), name.to_string().into(), service.into()]
                            }
                        },
                        log: self.log_file(name, unit),
                        env: self.layout.env(),
                    })
                    .collect();
                for unit in &units {
                    self.services.start(unit).map_err(service_error)?;
                }
                record.state = SandboxState::Running;
                self.state.put(lock, &record)?;
                Ok(units.into_iter().map(|u| u.label).collect())
            },
        )
    }

    /// Removes every service of the sandbox installed now, the proxy last;
    /// `stop_sandbox` calls this first.
    pub(super) fn stop_services(&self, name: &SandboxName) -> Result<()> {
        for label in self.installed_labels(name)? {
            self.services.stop(&label).map_err(service_error)?;
        }
        Ok(())
    }

    /// Whether the sandbox has services installed, running or not.
    pub(super) fn has_services(&self, name: &SandboxName) -> Result<bool> {
        Ok(!self.installed_labels(name)?.is_empty())
    }

    /// Each installed service of the sandbox and whether it runs.
    pub fn service_status(&self, name: &SandboxName) -> Result<Vec<(String, ServiceStatus)>> {
        Ok(self
            .installed_labels(name)?
            .into_iter()
            .map(|l| {
                let status = self.services.status(&l);
                (l, status)
            })
            .collect())
    }

    /// A runtime service's process: runs the command the sandbox's runtime
    /// declares as `service` in the sandbox, in a process group of its own,
    /// recorded as a session. Told to end (TERM, as the service manager
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
        let declared = adapter(kind).services();
        let command = declared
            .into_iter()
            .find(|s| s.name == service)
            .ok_or_else(|| Error::Session {
                what: format!("{kind} has no background service named {service}"),
            })?
            .command
            .into_words();
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
                let compiled = self.compile_policy(name, record.proxy_port)?;
                let (version, snapshot) =
                    self.state
                        .active_policy(name)?
                        .ok_or_else(|| Error::NoPolicy {
                            sandbox: name.to_string(),
                        })?;
                let (program, args) = command
                    .split_first()
                    .expect("a service command has a program");
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
        // As for `connect`: the members the service starts are recorded,
        // and what it leaves running keeps its session open.
        let waited = self.wait_session(&session, &mut child, Some(ended))?;
        self.finish_session(by, "service end", &session, waited)
    }

    /// Records a proxy that a service started, so `connect` knows it runs.
    pub(super) fn record_proxy(&self, by: &Actor, name: &SandboxName) -> Result<SessionId> {
        let me = std::process::id();
        self.write(
            by,
            "proxy start",
            Some(name.to_string()),
            |id| format!("session {id}"),
            |lock| {
                let (version, snapshot) =
                    self.state
                        .active_policy(name)?
                        .ok_or_else(|| Error::NoPolicy {
                            sandbox: name.to_string(),
                        })?;
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
                    // Its group only when it leads it, as under launchd:
                    // otherwise the group is its caller's.
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
        let Ok(entries) = std::fs::read_dir(self.logs_dir(name)) else {
            return Ok(Vec::new());
        };
        let proxy = self.log_file(name, Unit::Proxy);
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "log"))
            .collect();
        files.sort_by_key(|p| (*p != proxy, p.clone()));
        Ok(files)
    }
}

fn service_error(e: ServiceError) -> Error {
    Error::Session { what: e.what }
}

/// Sets `ended` on TERM, INT and HUP while it lives, instead of ending this
/// process: `launch` outlives them to stop the runtime, which runs in a
/// group of its own that the service manager does not signal, and to
/// record its end.
struct EndOn(Vec<signal_hook::SigId>);

impl EndOn {
    fn new(ended: &Arc<AtomicBool>) -> Result<Self> {
        let mut ids = Vec::new();
        for signal in [SIGTERM, SIGINT, SIGHUP] {
            let id = signal_hook::flag::register(signal, Arc::clone(ended)).map_err(|e| {
                Error::Session {
                    what: format!("cannot handle signal {signal}: {e}"),
                }
            })?;
            ids.push(id);
        }
        Ok(EndOn(ids))
    }
}

impl Drop for EndOn {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
