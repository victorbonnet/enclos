//! The state store: sandbox records, behind one interface (ADR 0010).
//!
//! Every write takes a [`StateLock`], so writing outside the lock does not
//! compile.

pub mod sqlite;

use std::fs::File;
use std::path::PathBuf;

use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::policy::{PolicySnapshot, PolicyVersion};
use crate::model::sandbox::{SandboxName, SandboxRecord};
use crate::model::session::{SessionId, SessionRecord};

/// Proof that this process holds the exclusive state lock. Released on drop.
///
/// Only a state store can create one, by taking the lock.
#[derive(Debug)]
pub struct StateLock {
    _file: Option<File>,
}

impl StateLock {
    /// Wraps a file on which this process holds an exclusive lock.
    fn held(file: File) -> Self {
        StateLock { _file: Some(file) }
    }

    /// A lock that guards nothing, for unit tests of other components.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        StateLock { _file: None }
    }
}

/// A change of the state database schema made by [`StateStore::migrate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The schema version before; 0 when the database was just created.
    pub from: u32,
    pub to: u32,
}

impl Migration {
    pub fn changed(self) -> bool {
        self.from != self.to
    }
}

pub type Result<T> = std::result::Result<T, StateError>;

/// Sandbox records, each change made under the state lock, and the network
/// log beside them.
pub trait StateStore: NetLogStore {
    /// Takes the exclusive state lock, waiting a few seconds for another
    /// enclos command to finish.
    fn lock(&self) -> Result<StateLock>;
    /// Creates the database if needed and applies pending schema migrations.
    fn migrate(&self, lock: &StateLock) -> Result<Migration>;
    fn get(&self, name: &SandboxName) -> Result<Option<SandboxRecord>>;
    fn list(&self) -> Result<Vec<SandboxRecord>>;
    fn put(&self, lock: &StateLock, rec: &SandboxRecord) -> Result<()>;
    fn remove(&self, lock: &StateLock, name: &SandboxName) -> Result<()>;

    /// Stores `snapshot` unless an identical one is stored, appends a policy
    /// version pointing to it, and makes that version the sandbox's active
    /// policy (ADR 0018).
    fn save_policy(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        snapshot: &PolicySnapshot,
        by: &Actor,
        restores: Option<u32>,
    ) -> Result<PolicyVersion>;
    /// The sandbox's active policy version and its snapshot.
    fn active_policy(&self, name: &SandboxName) -> Result<Option<(PolicyVersion, PolicySnapshot)>>;
    /// Every policy version of the sandbox, oldest first.
    fn policy_history(&self, name: &SandboxName) -> Result<Vec<PolicyVersion>>;

    /// Records a session that started; its `id` is ignored and assigned.
    fn put_session(&self, lock: &StateLock, session: &SessionRecord) -> Result<SessionId>;
    /// Records that a session ended.
    fn end_session(&self, lock: &StateLock, id: SessionId) -> Result<()>;
    /// The sandbox's sessions, oldest first; only those not ended yet when
    /// `running_only`.
    fn sessions(&self, name: &SandboxName, running_only: bool) -> Result<Vec<SessionRecord>>;
}

/// The network log (design §6). The proxy appends to it as connections
/// close, without the state lock: a log row changes no state.
pub trait NetLogStore {
    fn record(&self, event: &NetEvent) -> Result<()>;
    /// The sandbox's connections, oldest first, from `since` on.
    fn events(&self, sandbox: &SandboxName, since: Option<Timestamp>) -> Result<Vec<NetEvent>>;
    /// Each destination the proxy denied for the sandbox, most recent first.
    fn denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>>;
}

/// Why the state store could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("enclos is not initialized: {path} is missing. Run `enclos init` first")]
    NotInitialized { path: PathBuf },
    #[error(
        "another enclos command is changing state and holds {path}. Try again when it finishes"
    )]
    Locked { path: PathBuf },
    #[error(
        "{path} uses schema {found}, older than this enclos ({current}). Run `enclos init` to upgrade it"
    )]
    OutdatedSchema {
        path: PathBuf,
        found: u32,
        current: u32,
    },
    #[error(
        "{path} uses schema {found}, written by a newer enclos (this one knows {current}). Upgrade enclos"
    )]
    NewerSchema {
        path: PathBuf,
        found: u32,
        current: u32,
    },
    #[error(
        "{path} was written by an unreleased build of enclos whose schema {found} differs from this one's, so it cannot be upgraded. Remove its sandboxes with that build (`enclos sandbox rm <name>`) or move the enclos folder aside, then run `enclos init` and create them again"
    )]
    UnknownSchema { path: PathBuf, found: u32 },
    #[error("{path} holds a value enclos cannot read ({detail}). Restore state.db from a backup")]
    Corrupt { path: PathBuf, detail: String },
    #[error("cannot use {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("state database {path}: {source}")]
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
}
