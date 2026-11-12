//! The network log as a proxy writes it: in batches, on one thread.

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::{SqliteStateStore, netlog, probe_sources};
use crate::model::Timestamp;
use crate::model::net::{DeniedDestination, NetEvent};
use crate::model::sandbox::SandboxName;
use crate::state::{NetLogStore, Result, StateError};

/// A proxy's network log. The proxy logs each connection as it opens and as
/// it closes, from that connection's thread; one thread writes all the rows
/// waiting in one transaction, then leaves `state.db` free for as long as
/// that transaction held it, so that other writers get their turn. A write
/// still returns once its row is in the database.
///
/// A transaction per row, from each connection's thread, would keep the
/// write lock taken through an install's bursts of connections on a slow
/// disk, and other writes would wait past their 10 seconds.
pub struct NetLogWriter {
    store: Arc<SqliteStateStore>,
    writes: mpsc::Sender<Job>,
}

enum Write {
    Record(NetEvent, Option<String>),
    Finish(i64, NetEvent),
}

struct Job {
    write: Write,
    done: mpsc::Sender<std::result::Result<i64, Arc<StateError>>>,
}

impl NetLogWriter {
    /// Starts the writing thread, which ends with the writer.
    pub fn start(store: SqliteStateStore) -> NetLogWriter {
        let store = Arc::new(store);
        let (writes, jobs) = mpsc::channel();
        let writer = Arc::clone(&store);
        thread::spawn(move || write_batches(&writer, &jobs));
        NetLogWriter { store, writes }
    }

    fn write(&self, write: Write) -> Result<i64> {
        let (done, result) = mpsc::channel();
        let stopped = || StateError::Io {
            path: self.store.db.clone(),
            source: std::io::Error::other("the network log's writing thread stopped"),
        };
        self.writes
            .send(Job { write, done })
            .map_err(|_| stopped())?;
        result
            .recv()
            .map_err(|_| stopped())?
            .map_err(StateError::Shared)
    }
}

fn write_batches(store: &SqliteStateStore, jobs: &mpsc::Receiver<Job>) {
    while let Ok(first) = jobs.recv() {
        let batch: Vec<Job> = std::iter::once(first).chain(jobs.try_iter()).collect();
        let writes: Vec<&Write> = batch.iter().map(|job| &job.write).collect();
        let (rows, held) = match store.write_log(&writes) {
            Ok((rows, held)) => (rows.into_iter().map(Ok).collect(), held),
            Err(e) => {
                let e = Arc::new(e);
                (vec![Err(e); batch.len()], Duration::ZERO)
            }
        };
        for (job, row) in batch.into_iter().zip(rows) {
            // Gone when its connection's thread is.
            let _ = job.done.send(row);
        }
        thread::sleep(held);
    }
}

impl SqliteStateStore {
    /// Makes `writes` in one transaction; returns each one's row and how long
    /// the transaction held the write lock.
    fn write_log(&self, writes: &[&Write]) -> Result<(Vec<i64>, Duration)> {
        let mut conn = self.open()?;
        // Only candidate-tagged records need the optional host-only provenance database.
        // A missing or unreadable sidecar leaves the connection as ordinary traffic.
        let attached = writes
            .iter()
            .any(|write| matches!(write, Write::Record(_, Some(_))))
            && matches!(self.attach_probe_sources(&conn, false), Ok(true));
        let tx = conn.transaction().map_err(self.sqlite_err())?;
        let held = Instant::now();
        let rows = writes
            .iter()
            .map(|write| match write {
                Write::Record(event, tag) => {
                    probe_sources::record(&tx, event, tag.as_deref(), attached)
                }
                Write::Finish(row, event) => netlog::finish(&tx, *row, event).map(|()| *row),
            })
            .collect::<rusqlite::Result<Vec<i64>>>()
            .map_err(self.sqlite_err())?;
        tx.commit().map_err(self.sqlite_err())?;
        Ok((rows, held.elapsed()))
    }
}

impl NetLogStore for NetLogWriter {
    fn record_probe(&self, event: &NetEvent, tag: Option<&str>) -> Result<i64> {
        self.write(Write::Record(event.clone(), tag.map(str::to_owned)))
    }

    fn begin_probe(&self, sandbox: &SandboxName, tag: &str) -> Result<()> {
        self.store.begin_probe(sandbox, tag)
    }

    fn end_probe(&self, tag: &str) -> Result<()> {
        self.store.end_probe(tag)
    }

    fn denied_for_approval(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        self.store.denied_for_approval(sandbox)
    }

    fn record(&self, event: &NetEvent) -> Result<i64> {
        self.write(Write::Record(event.clone(), None))
    }

    fn finish(&self, row: i64, event: &NetEvent) -> Result<()> {
        self.write(Write::Finish(row, event.clone())).map(|_| ())
    }

    fn events(&self, sandbox: &SandboxName, since: Option<Timestamp>) -> Result<Vec<NetEvent>> {
        self.store.events(sandbox, since)
    }

    fn denied(&self, sandbox: &SandboxName) -> Result<Vec<DeniedDestination>> {
        self.store.denied(sandbox)
    }

    fn last_event(&self, sandbox: &SandboxName) -> Result<Option<Timestamp>> {
        self.store.last_event(sandbox)
    }
}

#[cfg(test)]
mod tests;
