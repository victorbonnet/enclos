//! The state store in a SQLite database (`state.db`), with the state lock
//! held on a separate lock file.

mod netlog;
mod policy;
mod schema;
#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, Row, TransactionBehavior, params};

use super::{Migration, NetLogStore, Result, StateError, StateLock, StateStore};
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::now;
use crate::model::policy::{PolicySnapshot, PolicyVersion};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};

/// How long `lock` waits for another enclos command to release the lock.
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(50);

pub struct SqliteStateStore {
    db: PathBuf,
    lock_file: PathBuf,
}

impl SqliteStateStore {
    pub fn new(db: impl Into<PathBuf>, lock_file: impl Into<PathBuf>) -> Self {
        SqliteStateStore {
            db: db.into(),
            lock_file: lock_file.into(),
        }
    }

    fn sqlite_err(&self) -> impl Fn(rusqlite::Error) -> StateError + '_ {
        |source| StateError::Sqlite {
            path: self.db.clone(),
            source,
        }
    }

    fn connect(&self, flags: OpenFlags) -> Result<Connection> {
        let conn = Connection::open_with_flags(&self.db, flags).map_err(self.sqlite_err())?;
        conn.busy_timeout(LOCK_WAIT).map_err(self.sqlite_err())?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(self.sqlite_err())?;
        Ok(conn)
    }

    /// Opens an existing database whose schema is the current one.
    fn open(&self) -> Result<Connection> {
        if !self.db.exists() {
            return Err(StateError::NotInitialized {
                path: self.db.clone(),
            });
        }
        let conn = self.connect(OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let found = user_version(&conn).map_err(self.sqlite_err())?;
        let current = schema::current();
        if found < current {
            return Err(StateError::OutdatedSchema {
                path: self.db.clone(),
                found,
                current,
            });
        }
        if found > current {
            return Err(StateError::NewerSchema {
                path: self.db.clone(),
                found,
                current,
            });
        }
        Ok(conn)
    }

    fn read_err(&self, e: policy::ReadError) -> StateError {
        match e {
            policy::ReadError::Sqlite(source) => self.sqlite_err()(source),
            policy::ReadError::Corrupt(detail) => StateError::Corrupt {
                path: self.db.clone(),
                detail,
            },
        }
    }

    fn sandbox_row(&self, row: &Row<'_>) -> Result<SandboxRecord> {
        let corrupt = |detail: String| StateError::Corrupt {
            path: self.db.clone(),
            detail,
        };
        let text = |i: usize| row.get::<_, String>(i).map_err(self.sqlite_err());
        let (name, backend, state, created_at) = (text(0)?, text(1)?, text(2)?, text(4)?);
        let reason: Option<String> = row.get(3).map_err(self.sqlite_err())?;
        Ok(SandboxRecord {
            name: name.parse().map_err(|e| corrupt(format!("{e}")))?,
            backend: backend.parse().map_err(|e| corrupt(format!("{e}")))?,
            state: match (state.as_str(), reason) {
                ("created", _) => SandboxState::Created,
                ("running", _) => SandboxState::Running,
                ("stopped", _) => SandboxState::Stopped,
                ("failed", reason) => SandboxState::Failed {
                    reason: reason.unwrap_or_default(),
                },
                (other, _) => return Err(corrupt(format!("unknown sandbox state `{other}`"))),
            },
            created_at: created_at
                .parse()
                .map_err(|e| corrupt(format!("created_at `{created_at}`: {e}")))?,
        })
    }
}

fn user_version(conn: &Connection) -> rusqlite::Result<u32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
}

fn state_columns(state: &SandboxState) -> (&'static str, Option<&str>) {
    match state {
        SandboxState::Created => ("created", None),
        SandboxState::Running => ("running", None),
        SandboxState::Stopped => ("stopped", None),
        SandboxState::Failed { reason } => ("failed", Some(reason)),
    }
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> StateError + '_ {
    |source| StateError::Io {
        path: path.to_owned(),
        source,
    }
}

impl StateStore for SqliteStateStore {
    fn lock(&self) -> Result<StateLock> {
        let file: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.lock_file)
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => StateError::NotInitialized {
                    path: self.lock_file.clone(),
                },
                _ => io_err(&self.lock_file)(source),
            })?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(StateLock::held(file)),
                Err(TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(StateError::Locked {
                        path: self.lock_file.clone(),
                    });
                }
                Err(TryLockError::Error(source)) => return Err(io_err(&self.lock_file)(source)),
            }
        }
    }

    fn migrate(&self, _lock: &StateLock) -> Result<Migration> {
        let mut conn =
            self.connect(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)?;
        std::fs::set_permissions(&self.db, std::fs::Permissions::from_mode(0o600))
            .map_err(io_err(&self.db))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(self.sqlite_err())?;
        let from = user_version(&tx).map_err(self.sqlite_err())?;
        let current = schema::current();
        if from > current {
            return Err(StateError::NewerSchema {
                path: self.db.clone(),
                found: from,
                current,
            });
        }
        for sql in &schema::MIGRATIONS[from as usize..] {
            tx.execute_batch(sql).map_err(self.sqlite_err())?;
        }
        tx.pragma_update(None, "user_version", current)
            .map_err(self.sqlite_err())?;
        tx.commit().map_err(self.sqlite_err())?;
        Ok(Migration { from, to: current })
    }

    fn get(&self, name: &SandboxName) -> Result<Option<SandboxRecord>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, backend, state, failed_reason, created_at
                 FROM sandboxes WHERE name = ?1",
            )
            .map_err(self.sqlite_err())?;
        let mut rows = stmt
            .query(params![name.as_str()])
            .map_err(self.sqlite_err())?;
        let row = rows.next().map_err(self.sqlite_err())?;
        row.map(|row| self.sandbox_row(row)).transpose()
    }

    fn list(&self) -> Result<Vec<SandboxRecord>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, backend, state, failed_reason, created_at
                 FROM sandboxes ORDER BY name",
            )
            .map_err(self.sqlite_err())?;
        let mut rows = stmt.query([]).map_err(self.sqlite_err())?;
        let mut records = Vec::new();
        while let Some(row) = rows.next().map_err(self.sqlite_err())? {
            records.push(self.sandbox_row(row)?);
        }
        Ok(records)
    }

    fn put(&self, _lock: &StateLock, rec: &SandboxRecord) -> Result<()> {
        let conn = self.open()?;
        let (state, reason) = state_columns(&rec.state);
        conn.execute(
            "INSERT INTO sandboxes (name, backend, state, failed_reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (name) DO UPDATE SET backend = excluded.backend,
                 state = excluded.state, failed_reason = excluded.failed_reason,
                 created_at = excluded.created_at",
            params![
                rec.name.as_str(),
                rec.backend.as_str(),
                state,
                reason,
                rec.created_at.to_string()
            ],
        )
        .map_err(self.sqlite_err())?;
        Ok(())
    }

    fn remove(&self, _lock: &StateLock, name: &SandboxName) -> Result<()> {
        let conn = self.open()?;
        conn.execute(
            "DELETE FROM sandboxes WHERE name = ?1",
            params![name.as_str()],
        )
        .map_err(self.sqlite_err())?;
        Ok(())
    }

    fn save_policy(
        &self,
        _lock: &StateLock,
        name: &SandboxName,
        snapshot: &PolicySnapshot,
        by: &Actor,
        restores: Option<u32>,
    ) -> Result<PolicyVersion> {
        let mut conn = self.open()?;
        policy::save(&mut conn, name, snapshot, by, now(), restores).map_err(self.sqlite_err())
    }

    fn active_policy(&self, name: &SandboxName) -> Result<Option<(PolicyVersion, PolicySnapshot)>> {
        let conn = self.open()?;
        policy::active(&conn, name).map_err(|e| self.read_err(e))
    }

    fn policy_history(&self, name: &SandboxName) -> Result<Vec<PolicyVersion>> {
        let conn = self.open()?;
        policy::history(&conn, name).map_err(|e| self.read_err(e))
    }
}

impl NetLogStore for SqliteStateStore {
    fn record(&self, event: &NetEvent) -> Result<()> {
        let conn = self.open()?;
        netlog::record(&conn, event).map_err(self.sqlite_err())
    }

    fn events(
        &self,
        sandbox: &SandboxName,
        profile: Option<&str>,
        since: Option<Timestamp>,
    ) -> Result<Vec<NetEvent>> {
        let conn = self.open()?;
        netlog::events(&conn, sandbox, profile, since).map_err(|e| self.read_err(e))
    }

    fn denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        let conn = self.open()?;
        netlog::denied(&conn, sandbox).map_err(|e| self.read_err(e))
    }
}
