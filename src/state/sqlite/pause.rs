//! Host pause records (`host_pause` and `sandbox_pauses`) in `state.db`.

use rusqlite::{Connection, OptionalExtension, Row, params};

use super::policy::ReadError;
use crate::model::Timestamp;
use crate::model::audit::Actor;
use crate::model::pause::{HostPauseRecord, SandboxPauseRecord, next_revision};
use crate::model::sandbox::SandboxName;

pub fn get_host(conn: &Connection) -> Result<Option<HostPauseRecord>, ReadError> {
    let row: Option<(i64, i64, String, String, String)> = conn
        .query_row(
            "SELECT revision, pause_all, by_user, by_host, at FROM host_pause WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((revision, pause_all, user, host, at)) = row else {
        return Ok(None);
    };
    let revision = u64::try_from(revision)
        .map_err(|_| ReadError::Corrupt(format!("host_pause revision `{revision}`")))?;
    let pause_all = match pause_all {
        0 => false,
        1 => true,
        other => {
            return Err(ReadError::Corrupt(format!(
                "host_pause pause_all `{other}`"
            )));
        }
    };
    let at = at
        .parse()
        .map_err(|e| ReadError::Corrupt(format!("host_pause at `{at}`: {e}")))?;
    Ok(Some(HostPauseRecord {
        revision,
        pause_all,
        by: Actor { user, host },
        at,
    }))
}

fn sandbox_row(row: &Row<'_>) -> Result<SandboxPauseRecord, ReadError> {
    let sandbox: String = row.get(0)?;
    let labels_json: String = row.get(1)?;
    let kept_json: String = row.get(2)?;
    let released: Option<String> = row.get(3)?;
    let at: String = row.get(4)?;
    let user: String = row.get(5)?;
    let host: String = row.get(6)?;

    let sandbox = sandbox
        .parse()
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses sandbox `{sandbox}`: {e}")))?;
    let labels: Vec<String> = serde_json::from_str(&labels_json)
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses labels `{labels_json}`: {e}")))?;
    let kept: Vec<String> = serde_json::from_str(&kept_json)
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses kept `{kept_json}`: {e}")))?;
    let released = released
        .map(|s| {
            s.parse()
                .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses released `{s}`: {e}")))
        })
        .transpose()?;
    let at = at
        .parse()
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses at `{at}`: {e}")))?;
    Ok(SandboxPauseRecord {
        sandbox,
        labels,
        kept,
        released,
        at,
        by: Actor { user, host },
    })
}

pub fn list_sandboxes(conn: &Connection) -> Result<Vec<SandboxPauseRecord>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT sandbox, labels, kept, released, at, by_user, by_host
         FROM sandbox_pauses ORDER BY sandbox",
    )?;
    let rows = stmt.query_map([], |row| Ok(sandbox_row(row)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r??);
    }
    Ok(out)
}

pub fn get_sandbox(
    conn: &Connection,
    sandbox: &SandboxName,
) -> Result<Option<SandboxPauseRecord>, ReadError> {
    let row = conn
        .query_row(
            "SELECT sandbox, labels, kept, released, at, by_user, by_host
             FROM sandbox_pauses WHERE sandbox = ?1",
            params![sandbox.as_str()],
            |row| Ok(sandbox_row(row)),
        )
        .optional()?;
    row.transpose()
}

fn current_revision(tx: &rusqlite::Transaction<'_>) -> Result<Option<u64>, ReadError> {
    let rev: Option<i64> = tx
        .query_row("SELECT revision FROM host_pause WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    rev.map(|r| {
        u64::try_from(r).map_err(|_| ReadError::Corrupt(format!("host_pause revision `{r}`")))
    })
    .transpose()
}

fn bump_revision(tx: &rusqlite::Transaction<'_>, at: Timestamp) -> Result<u64, ReadError> {
    let Some(prev) = current_revision(tx)? else {
        return Ok(0);
    };
    let next = next_revision(prev, at);
    let next_i64 = i64::try_from(next)
        .map_err(|_| ReadError::Corrupt(format!("host_pause revision overflow `{next}`")))?;
    tx.execute(
        "UPDATE host_pause SET revision = ?1 WHERE id = 1",
        params![next_i64],
    )?;
    Ok(next)
}

fn upsert_host_in_tx(
    tx: &rusqlite::Transaction<'_>,
    pause_all: bool,
    by: &Actor,
    at: Timestamp,
) -> Result<HostPauseRecord, ReadError> {
    let existing = get_host(tx)?;
    let record = match existing {
        Some(mut prev) => {
            prev.revision = next_revision(prev.revision, at);
            prev.pause_all = prev.pause_all || pause_all;
            let rev_i64 = i64::try_from(prev.revision).map_err(|_| {
                ReadError::Corrupt(format!("host_pause revision overflow `{}`", prev.revision))
            })?;
            tx.execute(
                "UPDATE host_pause SET revision = ?1, pause_all = ?2 WHERE id = 1",
                params![rev_i64, i64::from(prev.pause_all)],
            )?;
            prev
        }
        None => {
            let revision = next_revision(0, at);
            let rev_i64 = i64::try_from(revision).map_err(|_| {
                ReadError::Corrupt(format!("host_pause revision overflow `{revision}`"))
            })?;
            tx.execute(
                "INSERT INTO host_pause (id, revision, pause_all, by_user, by_host, at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    rev_i64,
                    i64::from(pause_all),
                    &by.user,
                    &by.host,
                    at.to_string(),
                ],
            )?;
            HostPauseRecord {
                revision,
                pause_all,
                by: by.clone(),
                at,
            }
        }
    };
    Ok(record)
}

fn upsert_sandbox_in_tx(
    tx: &rusqlite::Transaction<'_>,
    rec: &SandboxPauseRecord,
) -> Result<(), ReadError> {
    let labels_json = serde_json::to_string(&rec.labels)
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses labels encode: {e}")))?;
    let kept_json = serde_json::to_string(&rec.kept)
        .map_err(|e| ReadError::Corrupt(format!("sandbox_pauses kept encode: {e}")))?;
    let released = rec.released.map(|t| t.to_string());
    tx.execute(
        "INSERT INTO sandbox_pauses (sandbox, labels, kept, released, at, by_user, by_host)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (sandbox) DO UPDATE SET
             labels = excluded.labels,
             kept = excluded.kept,
             released = excluded.released,
             at = excluded.at,
             by_user = excluded.by_user,
             by_host = excluded.by_host",
        params![
            rec.sandbox.as_str(),
            labels_json,
            kept_json,
            released,
            rec.at.to_string(),
            &rec.by.user,
            &rec.by.host,
        ],
    )?;
    Ok(())
}

/// Creates or updates `host_pause` and upserts all `rows` into `sandbox_pauses`
/// in a single transaction, rolling back wholly on any error.
pub fn begin_pause(
    conn: &mut Connection,
    pause_all: bool,
    by: &Actor,
    at: Timestamp,
    rows: &[SandboxPauseRecord],
) -> Result<HostPauseRecord, ReadError> {
    let tx = conn.transaction()?;
    let record = upsert_host_in_tx(&tx, pause_all, by, at)?;
    for rec in rows {
        upsert_sandbox_in_tx(&tx, rec)?;
    }
    tx.commit()?;
    Ok(record)
}

pub fn ensure_host(
    conn: &mut Connection,
    pause_all: bool,
    by: &Actor,
    at: Timestamp,
) -> Result<HostPauseRecord, ReadError> {
    let tx = conn.transaction()?;
    let record = upsert_host_in_tx(&tx, pause_all, by, at)?;
    tx.commit()?;
    Ok(record)
}

pub fn put_sandbox(
    conn: &mut Connection,
    rec: &SandboxPauseRecord,
    at: Timestamp,
) -> Result<u64, ReadError> {
    let tx = conn.transaction()?;
    upsert_sandbox_in_tx(&tx, rec)?;
    let rev = bump_revision(&tx, at)?;
    tx.commit()?;
    Ok(rev)
}

pub fn release_sandbox(
    conn: &mut Connection,
    sandbox: &SandboxName,
    by: &Actor,
    at: Timestamp,
) -> Result<u64, ReadError> {
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE sandbox_pauses SET released = ?1, by_user = ?2, by_host = ?3 WHERE sandbox = ?4",
        params![at.to_string(), &by.user, &by.host, sandbox.as_str()],
    )?;
    let rev = bump_revision(&tx, at)?;
    tx.commit()?;
    Ok(rev)
}

pub fn clear_host(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM sandbox_pauses", [])?;
    tx.execute("DELETE FROM host_pause", [])?;
    tx.commit()
}
