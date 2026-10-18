//! Audit models: who ran which state-changing command, and how it ended.

use std::fmt;
use std::str::FromStr;

use jiff::SignedDuration;

use super::Timestamp;

/// Who ran a command, and on which host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub user: String,
    pub host: String,
}

/// What a state-changing command is about to do, recorded before it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub by: Actor,
    /// The command, such as `init` or `sandbox create`.
    pub command: String,
    /// What the command acts on, such as a sandbox name.
    pub target: Option<String>,
}

/// How a state-changing command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult {
    Ok,
    Failed,
}

impl AuditResult {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditResult::Ok => "ok",
            AuditResult::Failed => "failed",
        }
    }
}

/// The result of a command, recorded when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub result: AuditResult,
    /// What changed, or why it failed.
    pub message: String,
}

impl Outcome {
    pub fn ok(message: impl Into<String>) -> Self {
        Outcome {
            result: AuditResult::Ok,
            message: message.into(),
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Outcome {
            result: AuditResult::Failed,
            message: message.into(),
        }
    }
}

/// One audit entry: a command's intent and, once it ended, its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The number of the line that opened the entry.
    pub seq: u64,
    pub at: Timestamp,
    pub intent: Intent,
    /// `None` when the command never finished, for example after a crash.
    pub finished: Option<Finished>,
}

/// When and how an audit entry was closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub at: Timestamp,
    pub outcome: Outcome,
}

/// Which audit entries to return.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Only entries opened at or after this time.
    pub since: Option<Timestamp>,
}

/// What `enclos audit verify` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Lines read and checked.
    pub lines: u64,
    /// Entries opened in the log.
    pub entries: u64,
    /// Entries whose command never finished.
    pub unfinished: Vec<AuditEntry>,
    /// The first place where the chain is broken, if any.
    pub broken: Option<ChainBreak>,
}

impl VerifyReport {
    /// True when every line is intact and in its original order.
    pub fn intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// The first line where the audit log stops being trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The line number, starting at 1.
    pub line: u64,
    pub problem: BreakKind,
}

/// Why a line breaks the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// The line is not a complete audit record.
    Unreadable { reason: String },
    /// The line's content no longer matches its hash.
    Edited,
    /// The line does not follow the line before it.
    OutOfOrder,
    /// The line closes an entry that is not open.
    UnknownEntry { entry: u64 },
}

impl fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {} {}", self.line, self.problem)
    }
}

impl fmt::Display for BreakKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreakKind::Unreadable { reason } => {
                write!(f, "is not a valid audit record ({reason})")
            }
            BreakKind::Edited => write!(
                f,
                "was changed after it was written (its hash does not match its content)"
            ),
            BreakKind::OutOfOrder => write!(
                f,
                "does not follow the line before it: lines were deleted, inserted or reordered"
            ),
            BreakKind::UnknownEntry { entry } => {
                write!(f, "closes entry {entry}, which is not open at that point")
            }
        }
    }
}

/// How far back to look, such as `30m`, `12h`, `7d` or `2w`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Since(SignedDuration);

impl Since {
    pub fn duration(self) -> SignedDuration {
        self.0
    }
}

/// A `--since` value that is not a number followed by a unit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a duration: use a whole number followed by s, m, h, d or w, such as `30m` or `7d`"
)]
pub struct InvalidSince(pub String);

impl FromStr for Since {
    type Err = InvalidSince;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidSince(s.to_owned());
        let unit_at = s.len().checked_sub(1).ok_or_else(invalid)?;
        let (number, unit) = s.split_at(unit_at);
        let seconds_per_unit: i64 = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            "w" => 604_800,
            _ => return Err(invalid()),
        };
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let count: i64 = number.parse().map_err(|_| invalid())?;
        let seconds = count.checked_mul(seconds_per_unit).ok_or_else(invalid)?;
        Ok(Since(SignedDuration::from_secs(seconds)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_since_values() {
        let secs = |s: &str| s.parse::<Since>().unwrap().duration().as_secs();
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("30m"), 1_800);
        assert_eq!(secs("12h"), 43_200);
        assert_eq!(secs("7d"), 604_800);
        assert_eq!(secs("2w"), 1_209_600);
    }

    #[test]
    fn rejects_malformed_since_values() {
        for s in [
            "",
            "d",
            "7",
            "7y",
            "-7d",
            "1.5h",
            "7 d",
            "99999999999999999999d",
        ] {
            assert!(s.parse::<Since>().is_err(), "{s}");
        }
    }

    #[test]
    fn chain_break_messages_name_the_line() {
        let brk = ChainBreak {
            line: 3,
            problem: BreakKind::OutOfOrder,
        };
        assert!(brk.to_string().starts_with("line 3 does not follow"));
    }
}
