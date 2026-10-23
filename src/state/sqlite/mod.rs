//! The state store in a SQLite database (`state.db`), with the state lock
//! held on a separate lock file.

mod agents;
mod netlog;
mod policy;
mod schema;
mod secrets;
mod sessions;
#[cfg(test)]
mod tests;

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, Row, TransactionBehavior, params};

use super::{Migration, NetLogStore, Result, StateError, StateLock, StateStore, UnreadableRecord};
use crate::model::Timestamp;
use crate::model::agent::{AgentName, AgentRecord};
use crate::model::audit::Actor;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::now;
use crate::model::policy::{PendingPolicy, PolicySnapshot, PolicyVersion, SnapshotId};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::secret::{SecretRecord, SecretRef};
use crate::model::session::{ProcessRef, SessionId, SessionRecord};

/// How long `lock` waits for another enclos command to release the lock.
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(50);

pub struct SqliteStateStore {
    db: PathBuf,
    lock_file: PathBuf,
    /// Set once `open` has compared the schema with the migrations: one
    /// command opens the database several times.
    schema_checked: OnceLock<()>,
}

impl SqliteStateStore {
    pub fn new(db: impl Into<PathBuf>, lock_file: impl Into<PathBuf>) -> Self {
        SqliteStateStore {
            db: db.into(),
            lock_file: lock_file.into(),
            schema_checked: OnceLock::new(),
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
        if self.schema_checked.get().is_none() {
            self.check_schema(&conn, found)?;
            let _ = self.schema_checked.set(());
        }
        Ok(conn)
    }

    /// Refuses a database whose tables and columns differ from what this
    /// enclos's own migrations make at its version: one written by an
    /// unreleased build whose migrations changed since.
    fn check_schema(&self, conn: &Connection, version: u32) -> Result<()> {
        let expected = Connection::open_in_memory().map_err(self.sqlite_err())?;
        for sql in &schema::MIGRATIONS[..version as usize] {
            expected.execute_batch(sql).map_err(self.sqlite_err())?;
        }
        if columns(conn).map_err(self.sqlite_err())?
            != columns(&expected).map_err(self.sqlite_err())?
        {
            return Err(StateError::UnknownSchema {
                path: self.db.clone(),
                found: version,
            });
        }
        Ok(())
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
        let template = text(5)?;
        let reason: Option<String> = row.get(3).map_err(self.sqlite_err())?;
        let proxy_port: i64 = row.get(6).map_err(self.sqlite_err())?;
        let runtime: Option<String> = row.get(7).map_err(self.sqlite_err())?;
        Ok(SandboxRecord {
            name: name.parse().map_err(|e| corrupt(format!("{e}")))?,
            backend: backend.parse().map_err(|e| corrupt(format!("{e}")))?,
            created_from: template.parse().map_err(|e| corrupt(format!("{e}")))?,
            proxy_port: u16::try_from(proxy_port)
                .map_err(|_| corrupt(format!("proxy_port {proxy_port}")))?,
            runtime: runtime
                .map(|a| a.parse().map_err(|e| corrupt(format!("{e}"))))
                .transpose()?,
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

/// Every table's columns, in order.
fn columns(conn: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT m.name, c.name FROM sqlite_schema AS m, pragma_table_info(m.name) AS c
         WHERE m.type = 'table' ORDER BY m.name, c.cid",
    )?;
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

fn state_columns(state: &SandboxState) -> (&'static str, Option<&str>) {
    match state {
        SandboxState::Created => ("created", None),
        SandboxState::Running => ("running", None),
        SandboxState::Stopped => ("stopped", None),
        SandboxState::Failed { reason } => ("failed", Some(reason)),
    }
}

/// Inserts the sandbox's record, followed by `on_conflict` (empty: a name
/// already recorded is an error).
fn insert_sandbox(
    conn: &Connection,
    rec: &SandboxRecord,
    on_conflict: &str,
) -> rusqlite::Result<()> {
    let (state, reason) = state_columns(&rec.state);
    conn.execute(
        &format!(
            "INSERT INTO sandboxes (name, backend, state, failed_reason, created_at, template, proxy_port, runtime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) {on_conflict}"
        ),
        params![
            rec.name.as_str(),
            rec.backend.as_str(),
            state,
            reason,
            rec.created_at.to_string(),
            rec.created_from.as_str(),
            rec.proxy_port,
            rec.runtime.map(|a| a.as_str())
        ],
    )?;
    Ok(())
}

/// Inserts or replaces the sandbox's record.
fn put_record(conn: &Connection, rec: &SandboxRecord) -> rusqlite::Result<()> {
    insert_sandbox(
        conn,
        rec,
        "ON CONFLICT (name) DO UPDATE SET backend = excluded.backend,
             state = excluded.state, failed_reason = excluded.failed_reason,
             created_at = excluded.created_at, template = excluded.template,
             proxy_port = excluded.proxy_port, runtime = excluded.runtime",
    )
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> StateError + '_ {
    |source| StateError::Io {
        path: path.to_owned(),
        source,
    }
}

impl StateStore for SqliteStateStore {
    fn lock(&self) -> Result<StateLock> {
        let started = Instant::now();
        loop {
            match self.try_lock()? {
                Some(lock) => return Ok(lock),
                None if started.elapsed() < LOCK_WAIT => std::thread::sleep(LOCK_POLL),
                None => {
                    return Err(StateError::Locked {
                        path: self.lock_file.clone(),
                    });
                }
            }
        }
    }

    fn try_lock(&self) -> Result<Option<StateLock>> {
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
        match file.try_lock() {
            Ok(()) => Ok(Some(StateLock::held(file))),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(source)) => Err(io_err(&self.lock_file)(source)),
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
        self.check_schema(&tx, from)?;
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
                "SELECT name, backend, state, failed_reason, created_at, template, proxy_port, runtime
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
                "SELECT name, backend, state, failed_reason, created_at, template, proxy_port, runtime
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

    fn list_each(&self) -> Result<Vec<std::result::Result<SandboxRecord, UnreadableRecord>>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                "SELECT name, backend, state, failed_reason, created_at, template, proxy_port, runtime
                 FROM sandboxes ORDER BY name",
            )
            .map_err(self.sqlite_err())?;
        let mut rows = stmt.query([]).map_err(self.sqlite_err())?;
        let mut records = Vec::new();
        while let Some(row) = rows.next().map_err(self.sqlite_err())? {
            records.push(match self.sandbox_row(row) {
                Ok(record) => Ok(record),
                Err(error @ StateError::Corrupt { .. }) => Err(UnreadableRecord {
                    name: row.get::<_, String>(0).map_err(self.sqlite_err())?,
                    error,
                }),
                Err(e) => return Err(e),
            });
        }
        Ok(records)
    }

    fn put(&self, _lock: &StateLock, rec: &SandboxRecord) -> Result<()> {
        let conn = self.open()?;
        put_record(&conn, rec).map_err(self.sqlite_err())
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

    fn create_sandbox(
        &self,
        _lock: &StateLock,
        rec: &SandboxRecord,
        snapshot: &PolicySnapshot,
        by: &Actor,
    ) -> Result<PolicyVersion> {
        let mut conn = self.open()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(self.sqlite_err())?;
        insert_sandbox(&tx, rec, "").map_err(self.sqlite_err())?;
        let version =
            policy::append(&tx, &rec.name, snapshot, by, now(), None).map_err(self.sqlite_err())?;
        tx.commit().map_err(self.sqlite_err())?;
        Ok(version)
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

    fn policy_version(
        &self,
        name: &SandboxName,
        number: u32,
    ) -> Result<Option<(PolicyVersion, PolicySnapshot)>> {
        let conn = self.open()?;
        policy::version_of(&conn, name, number).map_err(|e| self.read_err(e))
    }

    fn save_pending(
        &self,
        _lock: &StateLock,
        name: &SandboxName,
        pending: &PolicySnapshot,
        active: Option<&PolicySnapshot>,
        by: &Actor,
        restores: Option<u32>,
    ) -> Result<(Option<PolicyVersion>, PendingPolicy)> {
        let mut conn = self.open()?;
        policy::save_pending(&mut conn, name, pending, active, by, now(), restores)
            .map_err(self.sqlite_err())
    }

    fn pending_policy(
        &self,
        name: &SandboxName,
    ) -> Result<Option<(PendingPolicy, PolicySnapshot)>> {
        let conn = self.open()?;
        policy::pending(&conn, name).map_err(|e| self.read_err(e))
    }

    fn discard_pending(&self, _lock: &StateLock, name: &SandboxName) -> Result<bool> {
        let conn = self.open()?;
        policy::discard_pending(&conn, name).map_err(self.sqlite_err())
    }

    fn apply_pending(
        &self,
        _lock: &StateLock,
        name: &SandboxName,
        expected: &SnapshotId,
        by: &Actor,
    ) -> Result<Option<PolicyVersion>> {
        let mut conn = self.open()?;
        policy::apply_pending(&mut conn, name, expected, by, now()).map_err(self.sqlite_err())
    }

    fn put_session(&self, _lock: &StateLock, session: &SessionRecord) -> Result<SessionId> {
        let conn = self.open()?;
        sessions::insert(&conn, session).map_err(self.sqlite_err())
    }

    fn track(&self, _lock: &StateLock, id: SessionId, tracked: &[ProcessRef]) -> Result<()> {
        let conn = self.open()?;
        sessions::track(&conn, id, tracked).map_err(self.sqlite_err())
    }

    fn end_session(&self, _lock: &StateLock, id: SessionId) -> Result<()> {
        let conn = self.open()?;
        sessions::end(&conn, id, now()).map_err(self.sqlite_err())
    }

    fn start_session(
        &self,
        _lock: &StateLock,
        session: &SessionRecord,
        rec: &SandboxRecord,
    ) -> Result<SessionId> {
        let mut conn = self.open()?;
        (|| {
            let tx = conn.transaction()?;
            put_record(&tx, rec)?;
            let id = sessions::insert(&tx, session)?;
            tx.commit()?;
            Ok(id)
        })()
        .map_err(self.sqlite_err())
    }

    fn end_sessions(
        &self,
        _lock: &StateLock,
        ended: &[SessionId],
        rec: &SandboxRecord,
    ) -> Result<()> {
        let mut conn = self.open()?;
        let at = now();
        (|| {
            let tx = conn.transaction()?;
            for id in ended {
                sessions::end(&tx, *id, at)?;
            }
            put_record(&tx, rec)?;
            tx.commit()
        })()
        .map_err(self.sqlite_err())
    }

    fn sessions(&self, name: &SandboxName, running_only: bool) -> Result<Vec<SessionRecord>> {
        let conn = self.open()?;
        sessions::list(&conn, name, running_only).map_err(|e| self.read_err(e))
    }

    fn insert_agent(
        &self,
        _lock: &StateLock,
        sandbox: &SandboxName,
        agent: &AgentRecord,
    ) -> Result<()> {
        let conn = self.open()?;
        agents::insert(&conn, sandbox, agent).map_err(self.sqlite_err())
    }

    fn remove_agent(
        &self,
        _lock: &StateLock,
        sandbox: &SandboxName,
        name: &AgentName,
    ) -> Result<()> {
        let conn = self.open()?;
        agents::remove(&conn, sandbox, name).map_err(self.sqlite_err())
    }

    fn agents(&self, sandbox: &SandboxName) -> Result<Vec<AgentRecord>> {
        let conn = self.open()?;
        agents::list(&conn, sandbox).map_err(|e| self.read_err(e))
    }

    fn put_secret(&self, _lock: &StateLock, secret: &SecretRef) -> Result<bool> {
        let conn = self.open()?;
        secrets::put(&conn, secret, now()).map_err(self.sqlite_err())
    }

    fn remove_secret(&self, _lock: &StateLock, secret: &SecretRef) -> Result<bool> {
        let conn = self.open()?;
        secrets::remove(&conn, secret).map_err(self.sqlite_err())
    }

    fn secrets(&self, sandbox: &SandboxName) -> Result<Vec<SecretRecord>> {
        let conn = self.open()?;
        secrets::list(&conn, sandbox).map_err(|e| self.read_err(e))
    }
}

impl NetLogStore for SqliteStateStore {
    fn record(&self, event: &NetEvent) -> Result<i64> {
        let conn = self.open()?;
        netlog::record(&conn, event).map_err(self.sqlite_err())
    }

    fn finish(&self, row: i64, event: &NetEvent) -> Result<()> {
        let conn = self.open()?;
        netlog::finish(&conn, row, event).map_err(self.sqlite_err())
    }

    fn events(&self, sandbox: &SandboxName, since: Option<Timestamp>) -> Result<Vec<NetEvent>> {
        let conn = self.open()?;
        netlog::events(&conn, sandbox, since).map_err(|e| self.read_err(e))
    }

    fn denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        let conn = self.open()?;
        netlog::denied(&conn, sandbox).map_err(|e| self.read_err(e))
    }

    fn last_event(&self, sandbox: &SandboxName) -> Result<Option<Timestamp>> {
        let conn = self.open()?;
        netlog::last(&conn, sandbox).map_err(|e| self.read_err(e))
    }
}
