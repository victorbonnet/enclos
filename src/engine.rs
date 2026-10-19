//! The engine: the API every client calls, and the only place components
//! meet (design §9). Reads are not audited. Every write takes the state lock,
//! opens an audit entry, does the work and closes the entry, also on failure.

mod policy;
#[cfg(test)]
mod tests;

pub use policy::{PolicyApplied, PolicyView};

use std::path::PathBuf;

use crate::audit::AuditLog;
use crate::audit::jsonl::JsonlAuditLog;
use crate::backend::{self, Backend, Probe};
use crate::config;
use crate::error::Result;
use crate::layout::Layout;
use crate::model::audit::{Actor, AuditEntry, AuditFilter, Intent, Outcome, Since, VerifyReport};
use crate::model::now;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::BackendKind;
use crate::state::sqlite::SqliteStateStore;
use crate::state::{Migration, StateLock, StateStore};

pub struct Engine {
    layout: Layout,
    state: Box<dyn StateStore>,
    audit: Box<dyn AuditLog>,
    backends: Vec<Box<dyn Backend>>,
}

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
        Engine::new(
            layout,
            Box::new(state),
            Box::new(audit),
            backend::registered(),
        )
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
        }
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

    /// The first registered backend that works on this host.
    fn default_backend(&self) -> Option<BackendKind> {
        self.backends
            .iter()
            .find(|b| b.probe() == Probe::Available)
            .map(|b| b.kind())
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
