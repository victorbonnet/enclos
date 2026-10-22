//! A sandbox's background services (design §4, ADRs 0002, 0021): its proxy
//! and the services its runtime declares, run by the host's service manager
//! while the user is logged in. `sandbox start` installs them, so they come
//! back at each login; `sandbox stop` removes them.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Child;
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
use crate::model::audit::{Actor, Outcome};
use crate::model::now;
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::{SessionId, SessionKind, SessionRecord};
use crate::policy::sha256_hex;
use crate::runtime::{RuntimeService, ServiceName, adapter};
use crate::service::{LABEL_PREFIX, ServiceError, ServiceLabel, ServiceStatus, ServiceUnit};

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

    /// The proxy's log, whether the service manager or a session started
    /// it, so that `enclos logs` shows it either way.
    pub(super) fn proxy_log(&self, name: &SandboxName) -> PathBuf {
        self.log_file(name, Unit::Proxy)
    }

    pub(super) fn record(&self, name: &SandboxName) -> Result<SandboxRecord> {
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
        self.remove_services(by, name, "before sandbox start", IfUnrecorded::Stop)?
            .into_result()?;
        self.install_services(by, name).map_err(|error| {
            // None may stay installed: the undo removes them even when its
            // first entry cannot be written, as the start's entry records
            // the attempt.
            let undo = "after a failed sandbox start";
            match self.remove_services(by, name, undo, IfUnrecorded::RemoveAnyway) {
                Err(left) => Error::CleanupFailed {
                    error: Box::new(error),
                    left: left.to_string(),
                },
                Ok(Removal {
                    labels,
                    failed: None,
                    unrecorded: Some(audit),
                }) => Error::CleanupUnrecorded {
                    error: Box::new(error),
                    done: format!("removed {}", joined(&labels)),
                    audit: Box::new(audit),
                },
                Ok(removal) => match removal.into_result() {
                    Ok(_) => error,
                    Err(left) => Error::CleanupFailed {
                        error: Box::new(error),
                        left: left.to_string(),
                    },
                },
            }
        })
    }

    fn install_services(&self, by: &Actor, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        self.write(
            by,
            "sandbox start",
            Some(name.to_string()),
            |labels: &Vec<ServiceLabel>| joined(labels),
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
                    self.stop_sessions(
                        lock,
                        name,
                        |s| matches!(s.kind, SessionKind::Proxy | SessionKind::Service),
                        &format!(
                            "`enclos sandbox start` stopped there. End what still runs, then run `enclos sandbox start {name}` again"
                        ),
                        &mut Vec::new(),
                    )?;
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
                                        "--port".into(),
                                        record.proxy_port.to_string().into(),
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

    /// Removes every service of the sandbox installed now, the proxy last;
    /// `stop_sandbox` calls this first, and `start_sandbox` before it
    /// installs and after a failed install, as `why` says.
    ///
    /// Outside the lock, which a runtime service told to end needs to
    /// record its end, so two audit entries surround the removal: one
    /// naming what is about to be removed, closed before the first removal,
    /// then one saying what was removed and what is left. Nothing is written
    /// when none is installed. If the first entry cannot be written, this
    /// fails without removing anything, unless `if_unrecorded` says to go
    /// on. If the second cannot be written, the first still shows the
    /// removal began, and the [`Removal`] says why the result is not
    /// recorded.
    pub(super) fn remove_services(
        &self,
        by: &Actor,
        name: &SandboxName,
        why: &str,
        if_unrecorded: IfUnrecorded,
    ) -> Result<Removal> {
        let labels = self.installed_labels(name)?;
        if labels.is_empty() {
            return Ok(Removal {
                labels,
                failed: None,
                unrecorded: None,
            });
        }
        let target = Some(name.to_string());
        let message = format!("removing {} {why}", joined(&labels));
        let begun = self.note(by, "services remove", target.clone(), Outcome::ok(message));
        if if_unrecorded == IfUnrecorded::Stop {
            begun?;
        }
        let mut failed = None;
        for (i, label) in labels.iter().enumerate() {
            if let Err(e) = self.services.stop(label) {
                failed = Some((i, e));
                break;
            }
        }
        let outcome = match &failed {
            None => Outcome::ok(format!("removed {}", joined(&labels))),
            Some((i, e)) => {
                let (done, left) = labels.split_at(*i);
                Outcome::failed(format!(
                    "removed {}; could not remove {}: {e}; still installed: {}",
                    joined(done),
                    labels[*i],
                    joined(left)
                ))
            }
        };
        // When the first entry was not written either, this one still
        // records the whole removal.
        let unrecorded = self.note(by, "services removed", target, outcome).err();
        Ok(Removal {
            labels,
            failed: failed.map(|(_, e)| e),
            unrecorded,
        })
    }

    /// Whether the sandbox has services installed, running or not.
    pub(super) fn has_services(&self, name: &SandboxName) -> Result<bool> {
        Ok(!self.installed_labels(name)?.is_empty())
    }

    /// Whether the sandbox's service `unit` is installed, running or not.
    pub(super) fn unit_installed(&self, name: &SandboxName, unit: Unit) -> Result<bool> {
        let label = self.label(name, unit)?;
        Ok(self.installed_labels(name)?.contains(&label))
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
    /// own, recorded as a session of `service`, once it has stopped any
    /// session of `service` still open. Told to end (TERM, as the service
    /// manager does, INT or HUP), it stops the session's members and records
    /// the end, as failed when the program outlives that.
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
        // As the program will read them as it starts (ADR 0031).
        let mut watch = self.settings_watch(name, kind, service);
        let summary = |(session, _, replaced): &(SessionRecord, _, Vec<SessionId>)| {
            let earlier = replaced_earlier(service, replaced);
            match earlier {
                Some(earlier) => format!("session {}, after {earlier}", session.id),
                None => format!("session {}", session.id),
            }
        };
        let (session, mut child, _) =
            self.write(by, "launch", Some(name.to_string()), summary, |lock| {
                // Sessions stopped and ended before a failure are named in
                // the failed entry too.
                let mut replaced = Vec::new();
                let started = (|| -> Result<(SessionRecord, Child)> {
                    // A `launch` killed before it recorded its end leaves its
                    // session open, and maybe its runtime running (design §4).
                    self.stop_sessions(
                        lock,
                        name,
                        |s| s.kind == SessionKind::Service && s.service.as_deref() == Some(service),
                        &format!(
                            "a second {service} was not started. End what still runs, and the service manager starts the service again on its own; `enclos sandbox stop {name}` removes the service instead"
                        ),
                        &mut replaced,
                    )?;
                    if ended.load(Ordering::Relaxed) {
                        return Err(Error::Session {
                            what: format!("told to end before the {service} service of {name} started"),
                        });
                    }
                    self.start_service(lock, name, program, args, kind, service)
                })();
                let started = match (started, replaced_earlier(service, &replaced)) {
                    (Ok((session, child)), _) => Ok((session, child, replaced)),
                    (Err(error), None) => Err(error),
                    (Err(error), Some(done)) => Err(Error::FailedAfter {
                        error: Box::new(error),
                        done,
                    }),
                };
                self.failed_on_error(lock, name, "launch", started)
            })?;
        // Once the runtime's settings change, the program is asked to
        // restart, once: it exits, and the service manager starts it again.
        let mut restarting = false;
        let mut look = |notes: &mut Vec<String>| {
            let Some((settings, signal)) = watch.as_mut() else {
                return;
            };
            let Some(changed) = settings.settled(Instant::now()) else {
                return;
            };
            let files: Vec<String> = changed.iter().map(ToString::to_string).collect();
            let files = files.join(", ");
            let asked = match self.ask_restart(by, &session, *signal, &changed) {
                // Another command holds the lock: the next look asks.
                Ok(None) => return,
                Ok(Some(Ok(()))) => {
                    restarting = true;
                    format!("{files} changed: asked the {service} service to restart")
                }
                Ok(Some(Err(why))) => {
                    format!(
                        "{files} changed, but the {service} service was not asked to restart: {why}"
                    )
                }
                Err(e) => format!(
                    "{files} changed, but the {service} service was not asked to restart: {e}"
                ),
            };
            super::session::note(notes, asked);
            watch = None;
        };
        // As for `connect`, the members the service starts are recorded.
        // Unlike `connect`, what it leaves running is stopped: under a
        // service manager the service is its program, which the manager
        // starts again, and what it last left would run beside it.
        let mut waited = match self.wait_session(&session, &mut child, Some(ended), &mut look) {
            Ok(waited) => waited,
            Err(error) => return Err(self.record_unended(by, "service end", &session, error)),
        };
        self.stop_left(&session, &mut waited);
        let mut end = self.finish_session(by, "service end", &session, waited)?;
        end.restarting = restarting;
        Ok(end)
    }

    /// Starts the service's `program` in the sandbox and records it as a
    /// session, with the sandbox as `Running` (design §8 steps 2-4), under
    /// the state lock.
    fn start_service(
        &self,
        lock: &crate::state::StateLock,
        name: &SandboxName,
        program: &std::ffi::OsString,
        args: &[std::ffi::OsString],
        kind: crate::model::runtime::RuntimeKind,
        service: &str,
    ) -> Result<(SessionRecord, std::process::Child)> {
        // A service session whose `launch` was killed before it recorded its
        // end, at logout or by the service manager's timeout: its process is
        // gone, so it ends here.
        self.end_dead_sessions(lock, name, SessionKind::Service)?;
        let mut record = self.record(name)?;
        let compiled = self.compile_policy(name, record.proxy_port)?;
        let (version, snapshot) = self.active_policy(name)?;
        let launch = Launch {
            program: program.clone(),
            args: args.to_vec(),
            env: Vec::new(),
            // Even when `enclos launch` is run by hand in a terminal: a
            // service outlives it.
            in_terminal: false,
            service_port: None,
        };
        let ctx = self.sandbox_context(name, record.proxy_port);
        let mut wrapped = self.backend_of(name)?.wrap(&compiled, &ctx, &launch);
        let marker = self.new_marker(name)?;
        let (child, marked) =
            marker
                .spawn(wrapped.process_group(0))
                .map_err(|e| Error::Session {
                    what: format!("could not start the {kind} {service} service: {e}"),
                })?;
        let recorded = (|| -> Result<SessionRecord> {
            let root = reference_of_child(&child)?;
            self.name_marker(name, marked, &root)?;
            let mut session = SessionRecord {
                id: SessionId(0),
                sandbox: name.clone(),
                kind: SessionKind::Service,
                service: Some(service.to_owned()),
                version: version.version,
                snapshot: snapshot.id,
                compiled: Some(compiled.display().to_string()),
                // In a group made for it, which it leads.
                pgid: Some(child.id()),
                root,
                tracked: Vec::new(),
                started_at: now(),
                ended_at: None,
            };
            // Running again, also after a `launch` that failed and that the
            // service manager starts again.
            record.state = SandboxState::Running;
            session.id = self.state.start_session(lock, &session, &record)?;
            Ok(session)
        })();
        match recorded {
            Ok(session) => Ok((session, child)),
            Err(e) => Err(abandon(child, e, "the service")),
        }
    }

    /// Ends the sandbox's sessions of `kind` whose root process is gone.
    pub(super) fn end_dead_sessions(
        &self,
        lock: &crate::state::StateLock,
        name: &SandboxName,
        kind: SessionKind,
    ) -> Result<()> {
        for session in self.state.sessions(name, true)? {
            if session.kind != kind || is_same(&session.root)? {
                continue;
            }
            // What it tracked, or what holds its marker (ADR 0030), still
            // runs: the session stays open, for a stop to end it.
            // One that cannot be looked at stays open too, rather than
            // keep the new service from starting.
            let Ok((procs, marked)) = self.marked_listed(&session) else {
                continue;
            };
            if !crate::lifecycle::members::is_gone(&procs, &marked) {
                continue;
            }
            self.state.end_session(lock, session.id)?;
            self.forget_marker(&session);
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
                    service: None,
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

/// What `remove_services` does when the entry opening a removal cannot be
/// written.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum IfUnrecorded {
    /// Removes nothing and fails: the command changes nothing.
    Stop,
    /// Removes the services anyway, when none may stay installed.
    RemoveAnyway,
}

/// What `remove_services` did.
pub(super) struct Removal {
    /// The services installed when it began, the proxy last.
    pub labels: Vec<ServiceLabel>,
    /// The removal that failed; the services from it on are still installed.
    pub failed: Option<ServiceError>,
    /// Why the audit log does not record the removal's result.
    pub unrecorded: Option<Error>,
}

impl Removal {
    /// The services removed, or what failed: the removal, its audit entry,
    /// or both.
    pub fn into_result(self) -> Result<Vec<ServiceLabel>> {
        match (self.failed, self.unrecorded) {
            (None, None) => Ok(self.labels),
            (Some(e), None) => Err(e.into()),
            (failed, Some(audit)) => Err(Error::Unrecorded {
                what: match failed {
                    None => format!("removed {}", joined(&self.labels)),
                    Some(e) => e.to_string(),
                },
                audit: Box::new(audit),
            }),
        }
    }
}

/// Labels as an audit message lists them: `a, b`, or `none`.
fn joined(labels: &[ServiceLabel]) -> String {
    if labels.is_empty() {
        return "none".to_owned();
    }
    labels
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `launch` did before starting `service`, for its audit entry: the
/// sessions of `service` it stopped and ended, if any.
fn replaced_earlier(service: &str, ids: &[SessionId]) -> Option<String> {
    let list = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    match ids {
        [] => None,
        [_] => Some(format!(
            "stopping and ending {service} service session {list}, left by an earlier launch"
        )),
        _ => Some(format!(
            "stopping and ending {service} service sessions {list}, left by earlier launches"
        )),
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
            restart: None,
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

    /// launchd kills a runtime service's job at its `ExitTimeOut`, the stop
    /// timeout; `stop` waits for it to be gone at least that long.
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_waits_for_a_stop_longer_than_the_stop_timeout() {
        assert!(crate::service::launchd::UNLOAD_WAIT > STOP_TIMEOUT);
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
