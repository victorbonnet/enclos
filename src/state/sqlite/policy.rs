//! Policy snapshots and versions in `state.db` (ADR 0018). Snapshots are
//! insert-only; versions are append-only.

use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::policy::{Policy, PolicyInputs, PolicySnapshot, PolicyVersion, SnapshotId};
use crate::model::sandbox::SandboxName;

/// Why a policy could not be read back.
pub enum ReadError {
    Sqlite(rusqlite::Error),
    /// A stored value enclos cannot make sense of.
    Corrupt(String),
}

impl From<rusqlite::Error> for ReadError {
    fn from(e: rusqlite::Error) -> Self {
        ReadError::Sqlite(e)
    }
}

fn corrupt(detail: String) -> ReadError {
    ReadError::Corrupt(detail)
}

pub fn save(
    conn: &mut Connection,
    name: &SandboxName,
    snapshot: &PolicySnapshot,
    by: &Actor,
    at: Timestamp,
    restores: Option<u32>,
) -> rusqlite::Result<PolicyVersion> {
    let tx = conn.transaction()?;
    let version = append(&tx, name, snapshot, by, at, restores)?;
    tx.commit()?;
    Ok(version)
}

/// As `save`, inside the caller's transaction.
pub fn append(
    tx: &Transaction<'_>,
    name: &SandboxName,
    snapshot: &PolicySnapshot,
    by: &Actor,
    at: Timestamp,
    restores: Option<u32>,
) -> rusqlite::Result<PolicyVersion> {
    let inputs = serde_json::to_string(&snapshot.inputs).expect("policy inputs serialize");
    let policy = serde_json::to_string(&snapshot.policy).expect("policies serialize");
    tx.execute(
        "INSERT INTO policy_snapshots (id, inputs, policy) VALUES (?1, ?2, ?3)
         ON CONFLICT (id) DO NOTHING",
        params![snapshot.id.0, inputs, policy],
    )?;
    let version: u32 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE sandbox = ?1",
        params![name.as_str()],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO policy_versions (sandbox, version, snapshot, by_user, by_host, at, restores)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            name.as_str(),
            version,
            snapshot.id.0,
            by.user,
            by.host,
            at.to_string(),
            restores
        ],
    )?;
    tx.execute(
        "UPDATE sandboxes SET active_version = ?2 WHERE name = ?1",
        params![name.as_str(), version],
    )?;
    Ok(PolicyVersion {
        version,
        snapshot: snapshot.id.clone(),
        by: by.clone(),
        at,
        restores,
    })
}

const VERSION_COLUMNS: &str = "v.version, v.snapshot, v.by_user, v.by_host, v.at, v.restores";

fn version(row: &Row<'_>) -> Result<PolicyVersion, ReadError> {
    let at: String = row.get(4)?;
    Ok(PolicyVersion {
        version: row.get(0)?,
        snapshot: SnapshotId(row.get(1)?),
        by: Actor {
            user: row.get(2)?,
            host: row.get(3)?,
        },
        at: at
            .parse()
            .map_err(|e| corrupt(format!("policy version time `{at}`: {e}")))?,
        restores: row.get(5)?,
    })
}

pub fn active(
    conn: &Connection,
    name: &SandboxName,
) -> Result<Option<(PolicyVersion, PolicySnapshot)>, ReadError> {
    let sql = format!(
        "SELECT {VERSION_COLUMNS}, s.inputs, s.policy
         FROM sandboxes b
         JOIN policy_versions v ON v.sandbox = b.name AND v.version = b.active_version
         JOIN policy_snapshots s ON s.id = v.snapshot
         WHERE b.name = ?1"
    );
    let row = conn
        .query_row(&sql, params![name.as_str()], |row| {
            Ok((
                version(row),
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .optional()?;
    let Some((version, inputs, policy)) = row else {
        return Ok(None);
    };
    let version = version?;
    let inputs: PolicyInputs =
        serde_json::from_str(&inputs).map_err(|e| corrupt(format!("snapshot inputs: {e}")))?;
    let policy: Policy =
        serde_json::from_str(&policy).map_err(|e| corrupt(format!("snapshot policy: {e}")))?;
    let snapshot = PolicySnapshot {
        id: version.snapshot.clone(),
        inputs,
        policy,
    };
    Ok(Some((version, snapshot)))
}

pub fn history(conn: &Connection, name: &SandboxName) -> Result<Vec<PolicyVersion>, ReadError> {
    let sql = format!(
        "SELECT {VERSION_COLUMNS} FROM policy_versions v WHERE v.sandbox = ?1 ORDER BY v.version"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![name.as_str()])?;
    let mut versions = Vec::new();
    while let Some(row) = rows.next()? {
        versions.push(version(row)?);
    }
    Ok(versions)
}
