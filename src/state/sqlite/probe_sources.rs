//! Diagnostic provenance lives beside the log, without changing its released schema.
//! A client-supplied tag is trusted only while the host has registered that exact run.
use super::log_writer::Write;
use super::*;
use std::io::ErrorKind;

impl SqliteStateStore {
    fn probe_sources_path(&self) -> PathBuf {
        self.db.with_file_name(crate::layout::PROBE_SOURCES_FILE)
    }
    fn attach_probe_sources(&self, conn: &Connection, create: bool) -> Result<bool> {
        let path = self.probe_sources_path();
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
        // A removed sandbox takes its log rows with it: their provenance goes too.
        conn.execute(
            "DELETE FROM probe_sources.events WHERE NOT EXISTS (SELECT 1 FROM main.net_events n \
             WHERE n.id = probe_sources.events.event AND n.sandbox = probe_sources.events.sandbox \
             AND n.at = probe_sources.events.at)",
            [],
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
    /// Records a connection as the proxy's batched writer does, as a batch
    /// of one.
    pub(super) fn record_probe_event(&self, event: &NetEvent, tag: Option<&str>) -> Result<i64> {
        let record = Write::Record(event.clone(), tag.map(str::to_owned));
        let (rows, _) = self.write_log(&[&record])?;
        Ok(rows[0])
    }
    /// Which of a batch's records, given as each one's event and tag, a run
    /// the host registered has tagged. The runs are read on a connection of
    /// their own, before the log's transaction: a tag no run registered, such
    /// as one a sandbox made up, never brings the side database and its lock
    /// into that transaction. `None` when the side database is not attached
    /// to `conn`; when it is, the records marked `true` get their provenance
    /// there. A side database that cannot be read leaves every record
    /// ordinary (ADR 0059).
    pub(super) fn registered_probes(
        &self,
        conn: &Connection,
        tagged: &[Option<(&NetEvent, &str)>],
    ) -> Option<Vec<bool>> {
        if tagged.iter().all(Option::is_none) {
            return None;
        }
        let path = self.probe_sources_path();
        if !path.exists() {
            return None;
        }
        let read = || -> rusqlite::Result<Vec<bool>> {
            let runs = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            runs.busy_timeout(self.write_wait)?;
            let mut registered = runs.prepare(
                "SELECT EXISTS (SELECT 1 FROM runs WHERE tag=?1 AND sandbox=?2 AND expires>=?3)",
            )?;
            tagged
                .iter()
                .map(|record| match record {
                    None => Ok(false),
                    Some((event, tag)) => registered.query_row(
                        params![tag, event.sandbox.as_str(), netlog::fixed(event.at)],
                        |row| row.get(0),
                    ),
                })
                .collect()
        };
        let registered = match read() {
            Ok(registered) if registered.contains(&true) => registered,
            Ok(_) => return None,
            Err(e) => {
                eprintln!(
                    "enclos: diagnostic run metadata cannot be read: {}",
                    self.sqlite_err()(e)
                );
                return None;
            }
        };
        match self.attach_probe_sources(conn, false) {
            Ok(true) => Some(registered),
            // Attached, but no longer as it was just read: no record counts
            // as diagnostic.
            Ok(false) => Some(vec![false; tagged.len()]),
            Err(e) => {
                eprintln!("enclos: diagnostic run metadata cannot be read: {e}");
                None
            }
        }
    }
    /// Holds the side database's write lock, which a log transaction that
    /// writes provenance takes as it begins and keeps until both databases
    /// have committed. SQLite commits attached databases one after the
    /// other, so a read that did not wait for it could see a run's log row
    /// before its provenance and count the row as ordinary. `None` when there
    /// is nothing to wait for: no side database, or one no one can write.
    fn settled_probe_sources(&self) -> Option<Connection> {
        let path = self.probe_sources_path();
        if !path.exists() {
            return None;
        }
        let lock = || -> rusqlite::Result<Connection> {
            let lock = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            lock.busy_timeout(self.write_wait)?;
            lock.execute_batch("BEGIN IMMEDIATE")?;
            Ok(lock)
        };
        match lock() {
            Ok(lock) => Some(lock),
            // No log transaction can write provenance there either.
            Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ReadOnly) => None,
            Err(e) => {
                eprintln!(
                    "enclos: reading refusals without waiting for diagnostic run metadata: {}",
                    self.sqlite_err()(e)
                );
                None
            }
        }
    }
    pub(super) fn user_denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        // Released, its transaction rolled back, once the read is done.
        let _settled = self.settled_probe_sources();
        let conn = self.open()?;
        let attached = matches!(self.attach_probe_sources(&conn, false), Ok(true));
        match netlog::denied_from(&conn, sandbox, attached) {
            // Attached but not readable: no row counts as diagnostic (ADR 0059).
            Err(e) if attached => {
                eprintln!(
                    "enclos: diagnostic run metadata cannot be read: {}",
                    self.read_err(e)
                );
                netlog::denied_from(&conn, sandbox, false)
            }
            read => read,
        }
        .map_err(|e| self.read_err(e))
    }
}

/// Records `event` in the caller's transaction and, given a `tag`, its
/// provenance in the attached side database, while the host still has that
/// run registered for the event's sandbox.
pub(super) fn record(
    conn: &Connection,
    event: &NetEvent,
    tag: Option<&str>,
) -> rusqlite::Result<i64> {
    let row = netlog::record(conn, event)?;
    if let Some(tag) = tag {
        conn.execute("INSERT INTO probe_sources.events SELECT ?1,?2,?3 WHERE EXISTS (SELECT 1 FROM probe_sources.runs WHERE tag=?4 AND sandbox=?2 AND expires>=?3)",params![row,event.sandbox.as_str(),netlog::fixed(event.at),tag])?;
    }
    Ok(row)
}
