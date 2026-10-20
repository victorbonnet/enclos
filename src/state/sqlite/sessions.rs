//! Sessions in `state.db` (design §8, ADR 0019).

use rusqlite::{Connection, Row, params};

use super::policy::ReadError;
use crate::model::Timestamp;
use crate::model::policy::SnapshotId;
use crate::model::sandbox::SandboxName;
use crate::model::session::{ProcessRef, SessionId, SessionRecord};

pub fn insert(conn: &Connection, s: &SessionRecord) -> rusqlite::Result<SessionId> {
    conn.execute(
        "INSERT INTO sessions (sandbox, kind, version, snapshot, compiled, root_pid,
             root_start, pgid, tracked, started_at, ended_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
        params![
            s.sandbox.as_str(),
            s.kind.as_str(),
            s.version,
            s.snapshot.0,
            s.compiled,
            s.root.pid,
            s.root.started,
            s.pgid,
            encode(&s.tracked),
            s.started_at.to_string(),
        ],
    )?;
    Ok(SessionId(conn.last_insert_rowid()))
}

pub fn end(conn: &Connection, id: SessionId, at: Timestamp) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE sessions SET ended_at = ?2 WHERE id = ?1 AND ended_at IS NULL",
        params![id.0, at.to_string()],
    )?;
    Ok(())
}

/// Replaces the members recorded for a session that has not ended.
pub fn track(conn: &Connection, id: SessionId, tracked: &[ProcessRef]) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE sessions SET tracked = ?2 WHERE id = ?1 AND ended_at IS NULL",
        params![id.0, encode(tracked)],
    )?;
    Ok(())
}

/// Processes as JSON: `[[pid, "start time"], ...]`.
fn encode(processes: &[ProcessRef]) -> String {
    let pairs: Vec<(u32, &str)> = processes
        .iter()
        .map(|p| (p.pid, p.started.as_str()))
        .collect();
    serde_json::to_string(&pairs).expect("pids and strings encode")
}

fn decode(text: &str) -> Result<Vec<ProcessRef>, ReadError> {
    let pairs: Vec<(u32, String)> = serde_json::from_str(text)
        .map_err(|e| corrupt(format!("session processes `{text}`: {e}")))?;
    Ok(pairs
        .into_iter()
        .map(|(pid, started)| ProcessRef { pid, started })
        .collect())
}

fn corrupt(detail: String) -> ReadError {
    ReadError::Corrupt(detail)
}

fn session(row: &Row<'_>) -> Result<SessionRecord, ReadError> {
    let sandbox: String = row.get(1)?;
    let kind: String = row.get(2)?;
    let tracked: String = row.get(9)?;
    let started_at: String = row.get(10)?;
    let ended_at: Option<String> = row.get(11)?;
    let time = |t: &str| {
        t.parse::<Timestamp>()
            .map_err(|e| corrupt(format!("session time `{t}`: {e}")))
    };
    Ok(SessionRecord {
        id: SessionId(row.get(0)?),
        sandbox: sandbox.parse().map_err(|e| corrupt(format!("{e}")))?,
        kind: kind.parse().map_err(corrupt)?,
        version: row.get(3)?,
        snapshot: SnapshotId(row.get(4)?),
        compiled: row.get(5)?,
        root: ProcessRef {
            pid: row.get(6)?,
            started: row.get(7)?,
        },
        pgid: row.get(8)?,
        tracked: decode(&tracked)?,
        started_at: time(&started_at)?,
        ended_at: ended_at.as_deref().map(time).transpose()?,
    })
}

pub fn list(
    conn: &Connection,
    sandbox: &SandboxName,
    running_only: bool,
) -> Result<Vec<SessionRecord>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT id, sandbox, kind, version, snapshot, compiled, root_pid, root_start,
                pgid, tracked, started_at, ended_at
         FROM sessions WHERE sandbox = ?1 AND (?2 = 0 OR ended_at IS NULL) ORDER BY id",
    )?;
    let mut rows = stmt.query(params![sandbox.as_str(), running_only])?;
    let mut sessions = Vec::new();
    while let Some(row) = rows.next()? {
        sessions.push(session(row)?);
    }
    Ok(sessions)
}
