//! The audit log: an append-only, hash-chained record of every
//! state-changing command (ADR 0010), behind one interface.

pub mod jsonl;

use std::path::PathBuf;

use crate::model::audit::{AuditEntry, AuditFilter, Intent, Outcome, VerifyReport};
use crate::state::StateLock;

/// An open audit entry. It borrows the state lock, so the entry is closed
/// while the lock is still held, and [`AuditLog::finish`] consumes it, so an
/// entry is closed at most once. Dropping it unfinished leaves an unfinished
/// entry in the log, as a crash would.
#[must_use = "close the audit entry with AuditLog::finish, also on failure"]
#[derive(Debug)]
pub struct AuditTicket<'l> {
    entry: u64,
    _lock: &'l StateLock,
}

impl<'l> AuditTicket<'l> {
    fn new(lock: &'l StateLock, entry: u64) -> Self {
        AuditTicket { entry, _lock: lock }
    }

    /// The number of the line that opened the entry.
    pub fn entry(&self) -> u64 {
        self.entry
    }
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// The audit log of state-changing commands.
pub trait AuditLog {
    /// Records a command's intent before it changes anything.
    fn begin<'l>(&self, lock: &'l StateLock, intent: Intent) -> Result<AuditTicket<'l>>;
    /// Records how the command ended, also when it failed.
    fn finish(&self, ticket: AuditTicket<'_>, outcome: Outcome) -> Result<()>;
    /// Returns the entries that match `filter`, oldest first.
    fn entries(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;
    /// Checks the hash chain and lists entries that never finished.
    fn verify(&self) -> Result<VerifyReport>;
    /// Fails as `begin` would on a damaged log, without writing: for a
    /// command that must change something outside the lock before it opens
    /// its entry.
    fn check(&self) -> Result<()>;
}

/// Why the audit log could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log {path} not found: enclos is not initialized. Run `enclos init` first")]
    NotFound { path: PathBuf },
    #[error(
        "audit log {path} is damaged: {reason}. No state-changing command runs until it is \
         repaired: keep the file under another name, such as `audit.jsonl.damaged`, and the \
         next command starts a new chain"
    )]
    Damaged { path: PathBuf, reason: String },
    #[error("cannot use audit log {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "cannot save the incomplete last line of the audit log to {path}: {source}. No \
         state-changing command runs until it can: fix the cause, such as a full disk or the \
         folder's permissions, then run the command again"
    )]
    SaveTorn {
        path: PathBuf,
        source: std::io::Error,
    },
}
