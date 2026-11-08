//! Diagnostic provenance lives beside the log, without changing its released schema.
//! A client-supplied tag is trusted only while the host has registered that exact run.
use super::*;
use std::io::ErrorKind;

impl SqliteStateStore {
    fn attach_probe_sources(&self, conn: &Connection, create: bool) -> Result<bool> {
        let path = self.db.with_file_name("probe-sources.db");
        if !path.exists() && !create {
            return Ok(false);
        }
        if create {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(_) => (),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => (),
                Err(e) => return Err(StateError::Io { path, source: e }),
            }
        }
        conn.execute(
            "ATTACH DATABASE ?1 AS probe_sources",
            [path.to_string_lossy().as_ref()],
        )
        .map_err(self.sqlite_err())?;
        if create {
            conn.execute_batch("CREATE TABLE IF NOT EXISTS probe_sources.runs (tag TEXT PRIMARY KEY,sandbox TEXT NOT NULL,expires TEXT NOT NULL); CREATE TABLE IF NOT EXISTS probe_sources.events (event INTEGER NOT NULL,sandbox TEXT NOT NULL,at TEXT NOT NULL,PRIMARY KEY(event,sandbox,at));").map_err(self.sqlite_err())?;
        }
        if !create {
            let tables:i64=conn.query_row("SELECT count(*) FROM probe_sources.sqlite_master WHERE type='table' AND name IN ('runs','events')",[],|row|row.get(0)).map_err(self.sqlite_err())?;
            if tables != 2 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn register_probe(&self, sandbox: &SandboxName, tag: &str) -> Result<()> {
        let conn = self.open()?;
        self.attach_probe_sources(&conn, true)?;
        let at = now();
        let expires = at
            .checked_add(jiff::SignedDuration::from_hours(1))
            .expect("one hour is representable");
        conn.execute(
            "DELETE FROM probe_sources.runs WHERE expires < ?1",
            [netlog::fixed(at)],
        )
        .map_err(self.sqlite_err())?;
        conn.execute(
            "INSERT INTO probe_sources.runs VALUES (?1,?2,?3)",
            params![tag, sandbox.as_str(), netlog::fixed(expires)],
        )
        .map_err(self.sqlite_err())?;
        Ok(())
    }
    pub(super) fn close_probe(&self, tag: &str) -> Result<()> {
        let conn = self.open()?;
        if self.attach_probe_sources(&conn, false)? {
            conn.execute("DELETE FROM probe_sources.runs WHERE tag=?1", [tag])
                .map_err(self.sqlite_err())?;
        }
        Ok(())
    }
    pub(super) fn record_probe_event(&self, event: &NetEvent, tag: Option<&str>) -> Result<i64> {
        let Some(tag) = tag else {
            return self.record(event);
        };
        let mut conn = self.open()?;
        if !matches!(self.attach_probe_sources(&conn, false), Ok(true)) {
            return netlog::record(&conn, event).map_err(self.sqlite_err());
        }
        // The log row and its provenance become visible together to other connections.
        let tx = conn.transaction().map_err(self.sqlite_err())?;
        let row = netlog::record(&tx, event).map_err(self.sqlite_err())?;
        tx.execute("INSERT INTO probe_sources.events SELECT ?1,?2,?3 WHERE EXISTS (SELECT 1 FROM probe_sources.runs WHERE tag=?4 AND sandbox=?2 AND expires>=?3)",params![row,event.sandbox.as_str(),netlog::fixed(event.at),tag]).map_err(self.sqlite_err())?;
        tx.commit().map_err(self.sqlite_err())?;
        Ok(row)
    }
    pub(super) fn user_denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        let conn = self.open()?;
        let attached = matches!(self.attach_probe_sources(&conn, false), Ok(true));
        netlog::denied_from(&conn, sandbox, attached).map_err(|e| self.read_err(e))
    }
}
