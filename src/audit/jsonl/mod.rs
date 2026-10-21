//! The audit log as a JSON Lines file (`audit.jsonl`), one hash-chained line
//! when a command starts and one when it ends. See `record.rs` for the format.

mod record;
#[cfg(test)]
mod tests;
mod verify;

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use record::{Body, GENESIS, Record, SCHEMA_VERSION, decode, encode, sha256_hex};
use verify::{Entries, split_lines};

use super::{AuditError, AuditLog, AuditTicket, Result};
use crate::model::audit::{AuditEntry, AuditFilter, Intent, Outcome, VerifyReport};
use crate::model::now;
use crate::state::StateLock;

/// How many bytes to read at a time when looking for the last line.
const TAIL_CHUNK: u64 = 4096;

pub struct JsonlAuditLog {
    path: PathBuf,
}

impl JsonlAuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        JsonlAuditLog { path: path.into() }
    }

    fn io_err(&self, source: std::io::Error) -> AuditError {
        match source.kind() {
            ErrorKind::NotFound => AuditError::NotFound {
                path: self.path.clone(),
            },
            _ => AuditError::Io {
                path: self.path.clone(),
                source,
            },
        }
    }

    fn damaged(&self, reason: impl Into<String>) -> AuditError {
        AuditError::Damaged {
            path: self.path.clone(),
            reason: reason.into(),
        }
    }

    /// The complete lines of the file, and the size of an incomplete last
    /// line if a crash left one. That line is split off before decoding,
    /// since a crash can also cut a character in half.
    fn read_all(&self) -> Result<(String, Option<u64>)> {
        let mut bytes = std::fs::read(&self.path).map_err(|e| self.io_err(e))?;
        let complete = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        let torn = (complete < bytes.len()).then(|| (bytes.len() - complete) as u64);
        bytes.truncate(complete);
        let text =
            String::from_utf8(bytes).map_err(|_| self.damaged("the file is not valid UTF-8"))?;
        Ok((text, torn))
    }

    /// The sequence number and hash of the last line, read from the end of
    /// the file. A missing or empty file starts a new chain.
    fn tail(&self) -> Result<(u64, String)> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok((0, GENESIS.to_owned())),
            Err(e) => return Err(self.io_err(e)),
        };
        let end = file.metadata().map_err(|e| self.io_err(e))?.len();
        self.tail_before(&mut file, end)
    }

    /// The sequence number and hash of the last line ending at or before
    /// byte `end`.
    fn tail_before(&self, file: &mut File, end: u64) -> Result<(u64, String)> {
        let Some(last) = last_line(file, end).map_err(|e| self.io_err(e))? else {
            return Ok((0, GENESIS.to_owned()));
        };
        let text = last
            .strip_suffix(b"\n")
            .ok_or_else(|| self.damaged("its last line is incomplete"))?;
        let text = std::str::from_utf8(text)
            .map_err(|_| self.damaged("its last line is not valid UTF-8"))?;
        let decoded =
            decode(text).map_err(|problem| self.damaged(format!("its last line {problem}")))?;
        Ok((decoded.record.seq, decoded.hash))
    }

    /// If a crash left an incomplete last line, moves it to
    /// `audit.jsonl.torn-<seq>` and records that in the log. Only that damage
    /// is recovered, and this checks only the line just before it, so call it
    /// only after [`Self::check_chain`] has refused any other damage. Called
    /// under the state lock, so the incomplete line cannot be a write still
    /// in progress.
    fn recover_torn_tail(&self) -> Result<()> {
        let mut file = match OpenOptions::new().read(true).write(true).open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(self.io_err(e)),
        };
        let end = file.metadata().map_err(|e| self.io_err(e))?.len();
        let Some(last) = last_line(&mut file, end).map_err(|e| self.io_err(e))? else {
            return Ok(());
        };
        if last.ends_with(b"\n") {
            return Ok(());
        }
        let keep = end - last.len() as u64;
        let (seq, _) = self.tail_before(&mut file, keep)?;
        let saved_to = format!("{}.torn-{}", self.file_name(), seq + 1);
        let saved_path = self.path.with_file_name(&saved_to);
        let mut saved = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&saved_path)
            .map_err(|e| self.io_err(e))?;
        saved
            .write_all(&last)
            .and_then(|()| saved.sync_all())
            .and_then(|()| file.set_len(keep))
            .and_then(|()| file.sync_all())
            .map_err(|e| self.io_err(e))?;
        self.write_record(Body::Recovered {
            removed_bytes: last.len() as u64,
            removed_sha256: sha256_hex(&last),
            saved_to,
        })?;
        Ok(())
    }

    fn file_name(&self) -> String {
        self.path.file_name().map_or_else(
            || "audit.jsonl".into(),
            |n| n.to_string_lossy().into_owned(),
        )
    }

    /// Checks the whole chain, recovers an incomplete last line, then appends
    /// one record. Any other damage, on any line, stops the write before the
    /// file changes.
    fn append(&self, body: Body) -> Result<u64> {
        self.check_chain()?;
        self.recover_torn_tail()?;
        self.write_record(body)
    }

    /// Verifies every line, as `enclos audit verify` does, and fails on the
    /// first break. An incomplete last line and unfinished entries are not
    /// breaks. A missing file starts a new chain. This reads the whole file,
    /// so each write takes time linear in the log's size.
    fn check_chain(&self) -> Result<()> {
        let report = match self.verify() {
            Ok(report) => report,
            Err(AuditError::NotFound { .. }) => return Ok(()),
            Err(e) => return Err(e),
        };
        match report.broken {
            Some(broken) => Err(self.damaged(broken.to_string())),
            None => Ok(()),
        }
    }

    /// Writes one record after the current last line, and flushes it to disk.
    fn write_record(&self, body: Body) -> Result<u64> {
        let (last_seq, prev) = self.tail()?;
        let record = Record {
            schema_version: SCHEMA_VERSION,
            seq: last_seq + 1,
            prev,
            at: now(),
            body,
        };
        let (mut line, _) = encode(&record).map_err(|e| self.io_err(std::io::Error::other(e)))?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| self.io_err(e))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|e| self.io_err(e))?;
        Ok(record.seq)
    }
}

/// Reads the last line of `file` that ends at or before byte `end`, with its
/// newline if it has one.
fn last_line(file: &mut File, mut end: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut tail: Vec<u8> = Vec::new();
    while end > 0 {
        let start = end.saturating_sub(TAIL_CHUNK);
        let mut chunk = vec![0; (end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        // A newline before the final byte ends the line before the last one.
        if let Some(pos) = tail[..tail.len() - 1].iter().rposition(|&b| b == b'\n') {
            tail.drain(..=pos);
            break;
        }
        end = start;
    }
    Ok((!tail.is_empty()).then_some(tail))
}

impl AuditLog for JsonlAuditLog {
    fn begin<'l>(&self, lock: &'l StateLock, intent: Intent) -> Result<AuditTicket<'l>> {
        let seq = self.append(Body::Begin {
            user: intent.by.user,
            host: intent.by.host,
            command: intent.command,
            target: intent.target,
        })?;
        Ok(AuditTicket::new(lock, seq))
    }

    fn finish(&self, ticket: AuditTicket<'_>, outcome: Outcome) -> Result<()> {
        self.append(Body::Finish {
            entry: ticket.entry(),
            result: outcome.result.into(),
            message: outcome.message,
        })?;
        Ok(())
    }

    fn entries(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let (content, _torn) = self.read_all()?;
        let mut entries = Entries::default();
        for line in split_lines(&content) {
            let unreadable = |problem| self.damaged(format!("line {} {problem}", line.number));
            let record = decode(line.text).map_err(unreadable)?.record;
            entries.add(record).map_err(unreadable)?;
        }
        let since = filter.since;
        Ok(entries
            .all()
            .into_iter()
            .filter(|e| since.is_none_or(|since| e.at >= since))
            .collect())
    }

    fn verify(&self) -> Result<VerifyReport> {
        let (content, torn) = self.read_all()?;
        Ok(verify::verify(&split_lines(&content), torn))
    }

    fn check(&self) -> Result<()> {
        self.check_chain()
    }
}
