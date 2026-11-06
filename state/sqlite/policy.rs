//! Policy snapshots and versions in `state.db` (ADR 0018). Snapshots are
//! insert-only; versions are append-only. A sandbox has at most one pending
//! policy beside them (design §7).

use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::policy::{
    PendingPolicy, Policy, PolicyInputs, PolicySnapshot, PolicyVersion, SnapshotId,
};
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

/// As `save`, inside the caller's transaction. The new active version
/// replaces any pending policy: what it would have applied is now either in
/// force or dropped.
pub fn append(
    tx: &Transaction<'_>,
    name: &SandboxName,
    snapshot: &PolicySnapshot,
    by: &Actor,
    at: Timestamp,
    restores: Option<u32>,
) -> rusqlite::Result<PolicyVersion> {
    insert_snapshot(tx, snapshot)?;
    append_version(tx, name, &snapshot.id, by, at, restores)
}

/// Stores `snapshot` unless an identical one is stored: the same id means
/// the same inputs, so the same text.
fn insert_snapshot(tx: &Transaction<'_>, snapshot: &PolicySnapshot) -> rusqlite::Result<()> {
    let inputs = serde_json::to_string(&snapshot.inputs).expect("policy inputs serialize");
    let policy = serde_json::to_string(&snapshot.policy).expect("policies serialize");
    tx.execute(
        "INSERT INTO policy_snapshots (id, inputs, policy, overrides) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (id) DO NOTHING",
        params![snapshot.id.0, inputs, policy, snapshot.overrides_text()],
    )?;
    Ok(())
}

/// Appends a version pointing to the stored snapshot `id`, makes it active
/// and drops the pending policy.
fn append_version(
    tx: &Transaction<'_>,
    name: &SandboxName,
    id: &SnapshotId,
    by: &Actor,
    at: Timestamp,
    restores: Option<u32>,
) -> rusqlite::Result<PolicyVersion> {
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
            id.0,
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
    tx.execute(
        "DELETE FROM pending_policies WHERE sandbox = ?1",
        params![name.as_str()],
    )?;
    Ok(PolicyVersion {
        version,
        snapshot: id.clone(),
        by: by.clone(),
        at,
        restores,
    })
}

/// Makes `pending` the sandbox's pending policy, in place of any other, and
/// with `active` a new active version first, in one transaction: a network
/// change made while a change is pending applies at once and is part of the
/// pending one too (design §7). `restores` is the version a pending
/// rollback restores.
pub fn save_pending(
    conn: &mut Connection,
    name: &SandboxName,
    pending: &PolicySnapshot,
    active: Option<&PolicySnapshot>,
    by: &Actor,
    at: Timestamp,
    restores: Option<u32>,
) -> rusqlite::Result<(Option<PolicyVersion>, PendingPolicy)> {
    let tx = conn.transaction()?;
    let version = active
        .map(|active| append(&tx, name, active, by, at, None))
        .transpose()?;
    insert_snapshot(&tx, pending)?;
    tx.execute(
        "INSERT INTO pending_policies (sandbox, snapshot, by_user, by_host, at, restores)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (sandbox) DO UPDATE SET snapshot = excluded.snapshot,
             by_user = excluded.by_user, by_host = excluded.by_host, at = excluded.at,
             restores = excluded.restores",
        params![
            name.as_str(),
            pending.id.0,
            by.user,
            by.host,
            at.to_string(),
            restores
        ],
    )?;
    tx.commit()?;
    Ok((
        version,
        PendingPolicy {
            snapshot: pending.id.clone(),
            by: by.clone(),
            at,
            restores,
        },
    ))
}

/// Drops the sandbox's pending policy; false when it had none.
pub fn discard_pending(conn: &Connection, name: &SandboxName) -> rusqlite::Result<bool> {
    let removed = conn.execute(
        "DELETE FROM pending_policies WHERE sandbox = ?1",
        params![name.as_str()],
    )?;
    Ok(removed > 0)
}

/// Makes the pending policy `expected` the active version, recorded as made
/// by `by`, in one transaction; `None` when the sandbox's pending policy is
/// not that snapshot (none, or another one saved since).
pub fn apply_pending(
    conn: &mut Connection,
    name: &SandboxName,
    expected: &SnapshotId,
    by: &Actor,
    at: Timestamp,
) -> rusqlite::Result<Option<PolicyVersion>> {
    let tx = conn.transaction()?;
    let pending: Option<(String, Option<u32>)> = tx
        .query_row(
            "SELECT snapshot, restores FROM pending_policies WHERE sandbox = ?1",
            params![name.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((snapshot, restores)) = pending else {
        return Ok(None);
    };
    if snapshot != expected.0 {
        return Ok(None);
    }
    let version = append_version(&tx, name, expected, by, at, restores)?;
    tx.commit()?;
    Ok(Some(version))
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

/// The snapshot from its stored columns: inputs, policy and overrides.
fn snapshot(
    id: SnapshotId,
    inputs: &str,
    policy: &str,
    overrides: String,
) -> Result<PolicySnapshot, ReadError> {
    let inputs: PolicyInputs =
        serde_json::from_str(inputs).map_err(|e| corrupt(format!("snapshot inputs: {e}")))?;
    let policy: Policy =
        serde_json::from_str(policy).map_err(|e| corrupt(format!("snapshot policy: {e}")))?;
    let short = id.short().to_owned();
    PolicySnapshot::new(id, inputs, policy, overrides).ok_or_else(|| {
        corrupt(format!(
            "snapshot {short}: the policy.toml it keeps is not the one its inputs name"
        ))
    })
}

pub fn active(
    conn: &Connection,
    name: &SandboxName,
) -> Result<Option<(PolicyVersion, PolicySnapshot)>, ReadError> {
    let sql = format!(
        "SELECT {VERSION_COLUMNS}, s.inputs, s.policy, s.overrides
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
                row.get::<_, String>(8)?,
            ))
        })
        .optional()?;
    let Some((version, inputs, policy, overrides)) = row else {
        return Ok(None);
    };
    let version = version?;
    let snapshot = snapshot(version.snapshot.clone(), &inputs, &policy, overrides)?;
    Ok(Some((version, snapshot)))
}

/// Version `number` of the sandbox's policy and its snapshot.
pub fn version_of(
    conn: &Connection,
    name: &SandboxName,
    number: u32,
) -> Result<Option<(PolicyVersion, PolicySnapshot)>, ReadError> {
    let sql = format!(
        "SELECT {VERSION_COLUMNS}, s.inputs, s.policy, s.overrides
         FROM policy_versions v JOIN policy_snapshots s ON s.id = v.snapshot
         WHERE v.sandbox = ?1 AND v.version = ?2"
    );
    let row = conn
        .query_row(&sql, params![name.as_str(), number], |row| {
            Ok((
                version(row),
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .optional()?;
    let Some((version, inputs, policy, overrides)) = row else {
        return Ok(None);
    };
    let version = version?;
    let snapshot = snapshot(version.snapshot.clone(), &inputs, &policy, overrides)?;
    Ok(Some((version, snapshot)))
}

pub fn pending(
    conn: &Connection,
    name: &SandboxName,
) -> Result<Option<(PendingPolicy, PolicySnapshot)>, ReadError> {
    let row = conn
        .query_row(
            "SELECT p.snapshot, p.by_user, p.by_host, p.at, s.inputs, s.policy, s.overrides,
                 p.restores
             FROM pending_policies p JOIN policy_snapshots s ON s.id = p.snapshot
             WHERE p.sandbox = ?1",
            params![name.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<u32>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((id, user, host, at, inputs, policy, overrides, restores)) = row else {
        return Ok(None);
    };
    let pending = PendingPolicy {
        snapshot: SnapshotId(id),
        by: Actor { user, host },
        at: at
            .parse()
            .map_err(|e| corrupt(format!("pending policy time `{at}`: {e}")))?,
        restores,
    };
    let snapshot = snapshot(pending.snapshot.clone(), &inputs, &policy, overrides)?;
    Ok(Some((pending, snapshot)))
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
