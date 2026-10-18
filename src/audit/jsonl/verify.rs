//! Reading `audit.jsonl` back: lines into entries, and the chain check.

use std::collections::BTreeMap;

use super::record::{Body, Decoded, GENESIS, Record, decode};
use crate::model::audit::{
    Actor, AuditEntry, BreakKind, ChainBreak, Finished, Intent, Outcome, VerifyReport,
};

/// One line of the file, numbered from 1.
pub struct Line<'a> {
    pub number: u64,
    pub text: &'a str,
    /// False for a last line without its newline, as a crash mid-write leaves.
    pub complete: bool,
}

pub fn split_lines(content: &str) -> Vec<Line<'_>> {
    let ends_with_newline = content.ends_with('\n');
    let texts: Vec<&str> = content.split_terminator('\n').collect();
    let count = texts.len();
    texts
        .into_iter()
        .enumerate()
        .map(|(i, text)| Line {
            number: i as u64 + 1,
            text,
            complete: ends_with_newline || i + 1 < count,
        })
        .collect()
}

/// Folds records into entries: a `begin` opens one, a `finish` closes it.
#[derive(Default)]
pub struct Entries {
    open: BTreeMap<u64, AuditEntry>,
    done: Vec<AuditEntry>,
}

impl Entries {
    pub fn add(&mut self, record: Record) -> Result<(), BreakKind> {
        match record.body {
            Body::Begin {
                user,
                host,
                command,
                target,
            } => {
                let entry = AuditEntry {
                    seq: record.seq,
                    at: record.at,
                    intent: Intent {
                        by: Actor { user, host },
                        command,
                        target,
                    },
                    finished: None,
                };
                self.open.insert(record.seq, entry);
            }
            Body::Finish {
                entry,
                result,
                message,
            } => {
                let mut opened = self
                    .open
                    .remove(&entry)
                    .ok_or(BreakKind::UnknownEntry { entry })?;
                opened.finished = Some(Finished {
                    at: record.at,
                    outcome: Outcome {
                        result: result.into(),
                        message,
                    },
                });
                self.done.push(opened);
            }
        }
        Ok(())
    }

    /// Entries that never finished, oldest first.
    pub fn unfinished(&self) -> Vec<AuditEntry> {
        self.open.values().cloned().collect()
    }

    /// Every entry, finished or not, oldest first.
    pub fn all(self) -> Vec<AuditEntry> {
        let mut all = self.done;
        all.extend(self.open.into_values());
        all.sort_by_key(|e| e.seq);
        all
    }
}

/// Checks every line: complete, unedited, in order, and closing open entries.
pub fn verify(lines: &[Line<'_>]) -> VerifyReport {
    let mut entries = Entries::default();
    let mut opened = 0;
    let mut prev = GENESIS.to_owned();
    let mut broken = None;
    for line in lines {
        match check(line, &prev) {
            Ok(Decoded { record, hash }) => {
                if matches!(record.body, Body::Begin { .. }) {
                    opened += 1;
                }
                if let Err(problem) = entries.add(record) {
                    broken = Some(ChainBreak {
                        line: line.number,
                        problem,
                    });
                    break;
                }
                prev = hash;
            }
            Err(problem) => {
                broken = Some(ChainBreak {
                    line: line.number,
                    problem,
                });
                break;
            }
        }
    }
    VerifyReport {
        lines: lines.len() as u64,
        entries: opened,
        unfinished: entries.unfinished(),
        broken,
    }
}

fn check(line: &Line<'_>, prev: &str) -> Result<Decoded, BreakKind> {
    if !line.complete {
        return Err(BreakKind::Unreadable {
            reason: "the line is incomplete, as when enclos stops while writing it".into(),
        });
    }
    let decoded = decode(line.text)?;
    if decoded.record.prev != prev || decoded.record.seq != line.number {
        return Err(BreakKind::OutOfOrder);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lines_and_flags_an_incomplete_last_line() {
        let lines = split_lines("a\nb\nc");
        let flags: Vec<_> = lines
            .iter()
            .map(|l| (l.number, l.text, l.complete))
            .collect();
        assert_eq!(flags, [(1, "a", true), (2, "b", true), (3, "c", false)]);
        assert!(split_lines("a\n").iter().all(|l| l.complete));
        assert!(split_lines("").is_empty());
    }

    #[test]
    fn an_empty_log_is_intact() {
        let report = verify(&[]);
        assert!(report.intact());
        assert_eq!((report.lines, report.entries), (0, 0));
    }
}
