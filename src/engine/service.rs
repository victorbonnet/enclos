//! A sandbox's background services (design §4, ADRs 0002, 0021): its proxy
//! and the services its runtime declares, run by the host's service manager
//! while the user is logged in. `sandbox start` installs them, so they come
//! back at each login; `sandbox stop` removes them.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::Engine;
use super::session::END_WAIT;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::audit::{Actor, Outcome};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::SessionKind;
use crate::model::unenforced::NotEnforced;
use crate::runtime::{RuntimeService, ServiceName, adapter};
use crate::service::{LABEL_PREFIX, ServiceError, ServiceLabel, ServiceStatus, ServiceUnit};

/// One of a sandbox's services: its proxy, its namespace holder for a
/// backend whose sessions join one (ADR 0039), or one its runtime declares,
/// by the name the runtime gives it, which is never `proxy` or `holder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Proxy,
    Holder,
    Runtime(ServiceName),
}

impl Unit {
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Proxy => "proxy",
            Unit::Holder => "holder",
            Unit::Runtime(name) => name.as_str(),
        }
    }
}

/// What `sandbox start` did: the services it installed, and what the
/// sandbox runs with not enforced on this host, every one accepted (ADR
/// 0038).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxStarted {
    pub labels: Vec<ServiceLabel>,
    pub not_enforced: Vec<NotEnforced>,
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
        let install = self.layout.install_id()?;
        Ok(format!("{LABEL_PREFIX}{install}.{name}."))
    }

    /// The service manager's label of one of the sandbox's services.
    pub fn label(&self, name: &SandboxName, unit: Unit) -> Result<ServiceLabel> {
        let text = format!("{}{}", self.label_prefix(name)?, unit.as_str());
        Ok(ServiceLabel::parse(&text).expect("a label is built from short names"))
    }

    /// The services `start_sandbox` installs for a runtime declaring
    /// `services`: the proxy, the namespace holder when the sandbox's
    /// sessions join one, then those, as declared.
    fn units_for(services: &[RuntimeService], holder: bool) -> Vec<Unit> {
        std::iter::once(Unit::Proxy)
            .chain(holder.then_some(Unit::Holder))
            .chain(services.iter().map(|s| Unit::Runtime(s.name)))
            .collect()
    }

    fn units(&self, record: &SandboxRecord) -> Vec<Unit> {
        let services = record
            .runtime
            .map(|kind| adapter(kind).services())
            .unwrap_or_default();
        Self::units_for(&services, self.holder_of(record.backend).is_some())
    }

    /// The labels `start_sandbox` installs.
    pub fn service_labels(&self, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let record = self.record(name)?;
        self.units(&record)
            .into_iter()
            .map(|u| self.label(name, u))
            .collect()
    }

    /// The labels of the sandbox installed now, the proxy last: those this
    /// enclos would install, and any other under the sandbox's prefix, such
    /// as one a runtime no longer declares.
    pub(super) fn installed_labels(&self, name: &SandboxName) -> Result<Vec<ServiceLabel>> {
        let mut labels = self.services.installed(&self.label_prefix(name)?)?;
        // Recorded running with nothing to show: it may be that the manager
        // is looking elsewhere, and calling that nothing to stop would leave
        // units running and starting at each login.
        if labels.is_empty()
            && matches!(self.state.get(name)?, Some(r) if r.state == SandboxState::Running)
        {
            self.services.can_list()?;
        }
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

    /// Makes the folder of the sandbox's logs, which a service's unit
    /// appends to: the service manager makes no folder, and does not start
    /// a unit whose log it cannot open.
    pub(super) fn create_logs_dir(&self, name: &SandboxName) -> Result<()> {
        let logs = self.logs_dir(name);
        std::fs::create_dir_all(&logs).map_err(|source| LayoutError::Io { path: logs, source })?;
        Ok(())
    }

    /// The proxy's log, whether the service manager or a session started
    /// it, so that `enclos logs` shows it either way.
    pub(super) fn proxy_log(&self, name: &SandboxName) -> PathBuf {
        self.log_file(name, Unit::Proxy)
    }

    /// The log of `enclos dashboard`'s program, beside the services' so
    /// that `enclos logs` shows it.
    pub(super) fn dashboard_log(&self, name: &SandboxName) -> PathBuf {
        self.logs_dir(name).join("dashboard.log")
    }

    pub(super) fn record(&self, name: &SandboxName) -> Result<SandboxRecord> {
        self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })
    }

    /// Installs the sandbox's proxy, its namespace holder and its runtime's
    /// services, replacing those it has already but a namespace holder that
    /// answers, whose namespace holds the sessions still open (ADR 0039). If
    /// one cannot be installed, none stays installed but that namespace
    /// holder, and the sandbox is marked failed. The services start on their
    /// own; `proxy_started` says when the proxy has. Each field the sandbox
    /// runs with not enforced on this host, every one accepted, is said in
    /// one line once its services are installed (ADR 0038), as each of its
    /// sessions says it too.
    pub fn start_sandbox(&self, by: &Actor, name: &SandboxName) -> Result<SandboxStarted> {
        self.require_sandbox(name)?;
        // Before anything is stopped: an unavailable manager (no login
        // session, another system) would leave the sandbox with nothing.
        self.services.available()?;
        // A damaged audit log would refuse the audited install after the
        // removal, leaving the sandbox with nothing.
        self.audit.check()?;
        // Nor is a service installed that could not start under its limits:
        // refused here, before anything is removed, rather than at each
        // start with only the service's log to say why. Each start checks
        // them again, under the service manager's own hard limit.
        let record = self.record(name)?;
        self.launch_limits(&record, &self.active_policy(name)?.1.policy)?;
        // Replacing it would split the sandbox: its open sessions would stay
        // in the old namespace, cut off from the proxy (ADR 0039).
        let kept = self.answering_holder(&record)?;
        let kept_ref = kept.as_slice();
        let kept = kept.as_ref();
        // Outside the lock, here and on failure: a runtime service told to
        // end stops its runtime and records its end, which needs the lock.
        self.remove_services(
            by,
            name,
            "before sandbox start",
            IfUnrecorded::Stop,
            kept_ref,
        )?
        .into_result()?;
        let started = self.install_services(by, name, kept).map_err(|error| {
            // None may stay installed: the undo removes them even when its
            // first entry cannot be written, as the start's entry records
            // the attempt.
            let undo = "after a failed sandbox start";
            match self.remove_services(by, name, undo, IfUnrecorded::RemoveAnyway, kept_ref) {
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
        })?;
        for n in &started.not_enforced {
            crate::notes::say(&n.gap.said_at_start(name.as_str()));
        }
        Ok(started)
    }

    /// What the service manager runs for the sandbox's service `unit`: this
    /// program, with the layout in its environment, and, but for the
    /// namespace holder, which reads no secret, what reaches the sandbox's
    /// secret stores (`store_env`).
    pub(super) fn service_unit(
        &self,
        record: &SandboxRecord,
        unit: Unit,
        store_env: &[(String, String)],
    ) -> Result<ServiceUnit> {
        let name = &record.name;
        let exe = self.exe.clone().ok_or_else(|| Error::Session {
            what: "cannot find the enclos program".into(),
        })?;
        let words = |words: &[&str]| words.iter().map(|w| (*w).into()).collect();
        let args = match unit {
            Unit::Proxy => words(&[
                "proxy",
                "run",
                name.as_str(),
                "--record",
                "--port",
                &record.proxy_port.to_string(),
            ]),
            Unit::Holder => words(&["holder", "run", name.as_str()]),
            Unit::Runtime(service) => words(&["launch", name.as_str(), service.as_str()]),
        };
        let stores = match unit {
            Unit::Holder => &[][..],
            Unit::Proxy | Unit::Runtime(_) => store_env,
        };
        Ok(ServiceUnit {
            label: self.label(name, unit)?,
            program: exe,
            args,
            log: self.log_file(name, unit),
            env: self
                .layout
                .env()
                .into_iter()
                .chain(stores.iter().cloned())
                .collect(),
            stop_timeout: STOP_TIMEOUT,
        })
    }

    /// Installs the sandbox's services, but `kept`, which stays as it runs.
    fn install_services(
        &self,
        by: &Actor,
        name: &SandboxName,
        kept: Option<&ServiceLabel>,
    ) -> Result<SandboxStarted> {
        let view = self.policy(name)?;
        self.write(
            by,
            "sandbox start",
            Some(name.to_string()),
            // Its entry lists what the sandbox runs with not enforced (ADR
            // 0038).
            |started: &SandboxStarted| {
                format!(
                    "{}{}",
                    joined(&started.labels),
                    super::unenforced::not_enforced_note(&started.not_enforced)
                )
            },
            |lock| {
                let mut record = self.record(name)?;
                let at = format!("at policy v{}", view.version.version);
                let not_enforced =
                    self.record_acceptances(lock, by, name, &view.snapshot.policy, &at)?;
                let installed = (|| -> Result<Vec<ServiceLabel>> {
                    self.backend_of(name)?;
                    let store_env =
                        self.service_store_env(&self.policy(name)?.snapshot.policy)?;
                    let units = self
                        .units(&record)
                        .into_iter()
                        .map(|unit| self.service_unit(&record, unit, &store_env))
                        .filter(|unit| !matches!(unit, Ok(u) if Some(&u.label) == kept))
                        .collect::<Result<Vec<ServiceUnit>>>()?;
                    self.create_logs_dir(name)?;
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
                Ok(SandboxStarted {
                    labels: installed?,
                    not_enforced,
                })
            },
        )
    }

    /// Removes every service of the sandbox installed now but those `kept`, the
    /// proxy last; `stop_sandbox` calls this first, keeping none, and
    /// `start_sandbox` before it installs and after a failed install, keeping
    /// a namespace holder that answers, as `why` says.
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
        kept: &[ServiceLabel],
    ) -> Result<Removal> {
        let mut labels = self.installed_labels(name)?;
        labels.retain(|l| !kept.contains(l));
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

    /// Whether the sandbox was started, so services of it are installed,
    /// running or not: its proxy's or its runtime's. A namespace holder
    /// alone does not count, as the first session of a sandbox that was
    /// never started installs it (ADR 0039).
    pub(super) fn has_services(&self, name: &SandboxName) -> Result<bool> {
        let holder = self.label(name, Unit::Holder)?;
        Ok(self.installed_labels(name)?.iter().any(|l| *l != holder))
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
        assert_eq!(Engine::units_for(&[], false), [Unit::Proxy]);
        assert_eq!(
            Engine::units_for(&[service("mail"), service("gateway")], false),
            [
                Unit::Proxy,
                Unit::Runtime(ServiceName::new("mail")),
                Unit::Runtime(ServiceName::new("gateway")),
            ]
        );
        // A sandbox whose sessions join a namespace holder has one, before
        // its runtime's services, also with none of those.
        assert_eq!(Engine::units_for(&[], true), [Unit::Proxy, Unit::Holder]);
        assert_eq!(
            Engine::units_for(&[service("gateway")], true),
            [
                Unit::Proxy,
                Unit::Holder,
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
}
