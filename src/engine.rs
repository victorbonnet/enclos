//! The engine: the API every client calls, and the only place components
//! meet (design §9). Reads are not audited. Every write takes the state lock,
//! opens an audit entry, does the work and closes the entry, also on failure.
//! Removing a sandbox's services is done outside the lock, which a runtime
//! service told to end needs, and is audited before and after instead
//! (`remove_services`).

mod channel;
mod compile;
mod history;
mod import;
mod listener;
mod net;
mod pending;
mod policy;
mod probe;
mod restart;
mod runtime;
mod sandbox;
mod secrets;
mod service;
mod session;
mod status;
#[cfg(test)]
mod tests;

pub use channel::ChannelSet;
pub use history::{PolicyDiff, PolicyHistory, Side};
pub use import::{Archive, LeftCopy};
pub use listener::ServiceWait;
pub use pending::{Discarded, EditFiles, Restarted};
pub use policy::{ChangeOutcome, PendingEnd, PolicyApplied, PolicyView, policy_differences};
pub use probe::TestReport;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use runtime::home_files_script;
pub use runtime::{Added, AgentAdded, AgentCheck, AgentDiff, AgentRemoved, FilesKept, InstallEnd};
pub use sandbox::{SandboxSpec, SandboxView, SessionView, StopReport};
pub use secrets::{SecretLeft, SecretSet, SecretView};
pub use service::{PROXY_WAIT, Unit};
pub use session::{Left, SessionEnd};
pub use status::{
    AgentKind, AgentList, AgentStatus, Disk, Fact, IDLE_DAYS, NetworkListener, Presence,
    RuntimeStatus, SandboxStatus, ServiceLine, ServiceState, StatusView, Suggestion, Unlisted,
    human_bytes, printable_line,
};

use std::path::PathBuf;
use std::time::Duration;

use crate::audit::AuditLog;
use crate::audit::jsonl::JsonlAuditLog;
use crate::backend::{self, Backend, Probe};
use crate::config;
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::lifecycle::process::PsError;
use crate::lifecycle::stop::Stopped;
use crate::model::audit::{Actor, AuditEntry, AuditFilter, Intent, Outcome, Since, VerifyReport};
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::policy::{PolicySnapshot, PolicyVersion};
use crate::model::sandbox::{BackendKind, SandboxName};
use crate::model::session::SessionRecord;
use crate::state::sqlite::SqliteStateStore;
use crate::state::{Migration, StateLock, StateStore};

pub struct Engine {
    layout: Layout,
    state: Box<dyn StateStore>,
    audit: Box<dyn AuditLog>,
    backends: Vec<Box<dyn Backend>>,
    /// The enclos program, to start the proxy and services with.
    exe: Option<std::path::PathBuf>,
    services: Box<dyn crate::service::ServiceManager>,
    /// Where secrets' values are kept (ADR 0022).
    secrets: Box<dyn crate::secrets::SecretStore>,
    /// How a session's members are stopped when `enclos launch` is told to
    /// end, and when it or `sandbox start` stops the sessions a new one
    /// replaces: `lifecycle::stop::stop`, unless a test stands in one that
    /// leaves them running.
    stop_members: StopMembers,
}

/// Stops a session's members within a grace period, as
/// `lifecycle::stop::stop` does.
type StopMembers = fn(&SessionRecord, Duration) -> std::result::Result<Stopped, PsError>;

/// What `enclos init` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    pub data: PathBuf,
    pub config: PathBuf,
    /// Folders and files that did not exist before.
    pub created: Vec<PathBuf>,
    pub migration: Migration,
    /// The backend written to a new `config.toml`, if one is available.
    pub default_backend: Option<BackendKind>,
}

impl InitReport {
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.created.is_empty() {
            parts.push(format!("created {} paths", self.created.len()));
        }
        if self.migration.from > 0 && self.migration.changed() {
            parts.push(format!(
                "upgraded state.db from schema {} to {}",
                self.migration.from, self.migration.to
            ));
        }
        if parts.is_empty() {
            "already initialized; nothing changed".to_owned()
        } else {
            parts.join("; ")
        }
    }
}

impl Engine {
    /// The engine with the real implementations, listed here explicitly.
    pub fn open(layout: Layout) -> Engine {
        let state = SqliteStateStore::new(layout.state_db(), layout.state_lock());
        let audit = JsonlAuditLog::new(layout.audit_log());
        let services = crate::service::host(layout.user_home());
        let secrets: Box<dyn crate::secrets::SecretStore> = match layout.install_id() {
            Ok(install) => crate::secrets::host(format!("enclos.{install}")),
            Err(e) => Box::new(crate::secrets::Unavailable {
                why: format!("enclos cannot tell this install apart from others: {e}"),
            }),
        };
        Engine::new(
            layout,
            Box::new(state),
            Box::new(audit),
            backend::registered(),
        )
        .with_services(services)
        .with_secrets(secrets)
    }

    pub fn new(
        layout: Layout,
        state: Box<dyn StateStore>,
        audit: Box<dyn AuditLog>,
        backends: Vec<Box<dyn Backend>>,
    ) -> Engine {
        Engine {
            layout,
            state,
            audit,
            backends,
            exe: std::env::current_exe().ok(),
            services: Box::new(crate::service::Unsupported {
                why: "this engine has no service manager",
            }),
            stop_members: crate::lifecycle::stop::stop,
            secrets: Box::new(crate::secrets::Unavailable {
                why: "this engine has no secret store".to_owned(),
            }),
        }
    }

    /// The same engine with another secret store.
    pub fn with_secrets(mut self, secrets: Box<dyn crate::secrets::SecretStore>) -> Engine {
        self.secrets = secrets;
        self
    }

    /// The same engine with another service manager.
    pub fn with_services(mut self, services: Box<dyn crate::service::ServiceManager>) -> Engine {
        self.services = services;
        self
    }

    /// Creates the enclos folders, `config.toml`, `state.db` and
    /// `audit.jsonl`, or upgrades `state.db`. Safe to run again.
    pub fn init(&self, by: &Actor, confirm: Confirm) -> Result<Planned<InitReport>> {
        let created = self.layout.missing();
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan {
                create: created,
                ..Plan::default()
            }));
        }
        // The top folders hold the lock and the audit log, so they come first.
        self.layout.create_roots()?;
        let report = self.write(by, "init", None, InitReport::summary, |lock| {
            self.layout.create_dirs()?;
            let migration = self.state.migrate(lock)?;
            let default_backend = self.default_backend();
            self.layout
                .write_config(&config::initial(default_backend))?;
            Ok(InitReport {
                data: self.layout.data().to_owned(),
                config: self.layout.config().to_owned(),
                created,
                migration,
                default_backend,
            })
        })?;
        Ok(Planned::Done(report))
    }

    /// Audit entries, oldest first, opened within `since` if given.
    pub fn audit(&self, since: Option<Since>) -> Result<Vec<AuditEntry>> {
        let filter = AuditFilter {
            since: since.and_then(|since| now().checked_sub(since.duration()).ok()),
        };
        Ok(self.audit.entries(&filter)?)
    }

    /// Checks the audit log's hash chain. Holds the state lock so that a
    /// command still running is not reported as unfinished.
    pub fn verify_audit(&self) -> Result<VerifyReport> {
        let _lock = self.state.lock()?;
        Ok(self.audit.verify()?)
    }

    /// Fails with the sandbox's name when it does not exist. Reads its record
    /// only: no lock, no process listing.
    pub fn require_sandbox(&self, name: &SandboxName) -> Result<()> {
        match self.state.get(name)? {
            Some(_) => Ok(()),
            None => Err(Error::NoSuchSandbox {
                name: name.to_string(),
            }),
        }
    }

    /// The sandbox's active policy version and its snapshot. A record
    /// without one is refused with the steps that make it again from its
    /// own backend and template.
    fn active_policy(&self, name: &SandboxName) -> Result<(PolicyVersion, PolicySnapshot)> {
        if let Some(active) = self.state.active_policy(name)? {
            return Ok(active);
        }
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        Err(Error::NoPolicy {
            sandbox: name.to_string(),
            backend: record.backend.to_string(),
            template: record.created_from.to_string(),
        })
    }

    /// The program started as the sandbox's proxy, for tests that stand one
    /// in.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_exe(mut self, exe: PathBuf) -> Engine {
        self.exe = Some(exe);
        self
    }

    /// The same engine stopping a session's members with `stop`, for tests
    /// of members that outlive being stopped.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_stop_members(mut self, stop: StopMembers) -> Engine {
        self.stop_members = stop;
        self
    }

    /// The first registered backend that works on this host.
    fn default_backend(&self) -> Option<BackendKind> {
        self.backends
            .iter()
            .find(|b| b.probe() == Probe::Available)
            .map(|b| b.kind())
    }

    /// Writes one closed audit entry, taking the lock only for the write,
    /// for a change made outside the lock (removing a sandbox's services,
    /// since a runtime service told to end needs the lock to record its
    /// end). The entry may come before or after the change. Not built on
    /// `write`, whose entry fails only when its work does.
    fn note(
        &self,
        by: &Actor,
        command: &str,
        target: Option<String>,
        outcome: Outcome,
    ) -> Result<()> {
        let lock = self.state.lock()?;
        let intent = Intent {
            by: by.clone(),
            command: command.to_owned(),
            target,
        };
        let ticket = self.audit.begin(&lock, intent)?;
        self.audit.finish(ticket, outcome)?;
        Ok(())
    }

    /// Runs `work` as one audited, state-changing command: takes the lock,
    /// opens an audit entry, runs the work and closes the entry with its
    /// outcome, also when the work fails.
    fn write<T>(
        &self,
        by: &Actor,
        command: &str,
        target: Option<String>,
        summary: impl FnOnce(&T) -> String,
        work: impl FnOnce(&StateLock) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let intent = Intent {
            by: by.clone(),
            command: command.to_owned(),
            target,
        };
        let ticket = self.audit.begin(&lock, intent)?;
        match work(&lock) {
            Ok(value) => {
                self.audit.finish(ticket, Outcome::ok(summary(&value)))?;
                Ok(value)
            }
            Err(error) => {
                // The work's error matters more; a failure to close the entry
                // leaves it unfinished, which `enclos audit verify` reports.
                let _ = self
                    .audit
                    .finish(ticket, Outcome::failed(error.to_string()));
                Err(error)
            }
        }
    }
}
