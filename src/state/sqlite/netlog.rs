//! The network log in `state.db` (design §6, ADR 0010).

use rusqlite::{Connection, Row, params};

use super::policy::ReadError;
use crate::model::Timestamp;
use crate::model::net::{DeniedDestination, NetEvent, Reason, Verdict};
use crate::model::sandbox::SandboxName;

/// Times in one fixed width, so that comparing them as text, as SQLite does,
/// orders them in time.
fn fixed(t: Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn record(conn: &Connection, e: &NetEvent) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO net_events (at, sandbox, host, port, method, address, verdict,
             reason, bytes_up, bytes_down, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            fixed(e.at),
            e.sandbox.as_str(),
            e.host,
            e.port,
            e.method,
            e.address,
            verdict_text(e.verdict),
            e.reason.map(|r| r.as_str()),
            e.bytes_up as i64,
            e.bytes_down as i64,
            e.duration_ms as i64,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn finish(conn: &Connection, row: i64, e: &NetEvent) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE net_events SET bytes_up = ?2, bytes_down = ?3, duration_ms = ?4 WHERE id = ?1",
        params![
            row,
            e.bytes_up as i64,
            e.bytes_down as i64,
            e.duration_ms as i64
        ],
    )?;
    Ok(())
}

fn verdict_text(v: Verdict) -> &'static str {
    match v {
        Verdict::Allowed => "allowed",
        Verdict::Denied => "denied",
    }
}

fn corrupt(detail: String) -> ReadError {
    ReadError::Corrupt(detail)
}

fn time(text: String) -> Result<Timestamp, ReadError> {
    text.parse()
        .map_err(|e| corrupt(format!("network log time `{text}`: {e}")))
}

fn reason(text: Option<String>) -> Result<Option<Reason>, ReadError> {
    text.map(|t| t.parse().map_err(corrupt)).transpose()
}

fn event(row: &Row<'_>) -> Result<NetEvent, ReadError> {
    let verdict: String = row.get(6)?;
    let sandbox: String = row.get(1)?;
    Ok(NetEvent {
        at: time(row.get(0)?)?,
        sandbox: sandbox.parse().map_err(|e| corrupt(format!("{e}")))?,
        host: row.get(2)?,
        port: row.get(3)?,
        method: row.get(4)?,
        address: row.get(5)?,
        verdict: match verdict.as_str() {
            "allowed" => Verdict::Allowed,
            "denied" => Verdict::Denied,
            other => return Err(corrupt(format!("unknown verdict `{other}`"))),
        },
        reason: reason(row.get(7)?)?,
        bytes_up: row.get::<_, i64>(8)? as u64,
        bytes_down: row.get::<_, i64>(9)? as u64,
        duration_ms: row.get::<_, i64>(10)? as u64,
    })
}

pub fn events(
    conn: &Connection,
    sandbox: &SandboxName,
    since: Option<Timestamp>,
) -> Result<Vec<NetEvent>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT at, sandbox, host, port, method, address, verdict, reason,
                bytes_up, bytes_down, duration_ms
         FROM net_events
         WHERE sandbox = ?1 AND (?2 IS NULL OR at >= ?2)
         ORDER BY at, id",
    )?;
    let since = since.map(fixed);
    let mut rows = stmt.query(params![sandbox.as_str(), since])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(event(row)?);
    }
    Ok(events)
}

pub fn denied(
    conn: &Connection,
    sandbox: &SandboxName,
) -> Result<Vec<DeniedDestination>, ReadError> {
    let mut stmt = conn.prepare(
        "SELECT host, port, reason, COUNT(*), MIN(at), MAX(at)
         FROM net_events WHERE sandbox = ?1 AND verdict = 'denied'
         GROUP BY host, port, reason ORDER BY MAX(at) DESC",
    )?;
    let mut rows = stmt.query(params![sandbox.as_str()])?;
    let mut denied = Vec::new();
    while let Some(row) = rows.next()? {
        denied.push(DeniedDestination {
            host: row.get(0)?,
            port: row.get(1)?,
            reason: reason(row.get(2)?)?.unwrap_or(Reason::NotAllowed),
            count: row.get::<_, i64>(3)? as u64,
            first: time(row.get(4)?)?,
            last: time(row.get(5)?)?,
        });
    }
    Ok(denied)
}
