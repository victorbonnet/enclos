//! The on-disk format of one `audit.jsonl` line.
//!
//! Each line is a JSON object whose last field is `hash`, the SHA-256 of the
//! line's own bytes without that field. Its `prev` field is the previous
//! line's `hash` (64 zeros on the first line), which chains the lines.
//!
//! ```text
//! {"schema_version":1,"seq":1,"prev":"000…","at":"…","kind":"begin","user":"alice","host":"mac","command":"init","hash":"…"}
//! {"schema_version":1,"seq":2,"prev":"…","at":"…","kind":"finish","entry":1,"result":"ok","message":"…","hash":"…"}
//! {"schema_version":1,"seq":3,"prev":"…","at":"…","kind":"recovered","removed_bytes":27,"removed_sha256":"…","saved_to":"audit.jsonl.torn-3","hash":"…"}
//! ```
//!
//! A `recovered` line records that a write found an incomplete last line, as
//! a crash while writing leaves, and moved it to `saved_to` first.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::Timestamp;
use crate::model::audit::{AuditResult, BreakKind};

pub const SCHEMA_VERSION: u32 = 1;
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const HASH_PREFIX: &str = ",\"hash\":\"";
const HASH_SUFFIX: &str = "\"}";
const HASH_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema_version: u32,
    pub seq: u64,
    pub prev: String,
    pub at: Timestamp,
    #[serde(flatten)]
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    /// A command's intent, written before it changes anything.
    Begin {
        user: String,
        host: String,
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
    },
    /// How the command opened at line `entry` ended.
    Finish {
        entry: u64,
        result: ResultField,
        message: String,
    },
    /// An incomplete last line, left by a crash while writing it, that was
    /// moved to `saved_to` before this line was written.
    Recovered {
        removed_bytes: u64,
        removed_sha256: String,
        saved_to: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultField {
    Ok,
    Failed,
}

impl From<AuditResult> for ResultField {
    fn from(result: AuditResult) -> Self {
        match result {
            AuditResult::Ok => ResultField::Ok,
            AuditResult::Failed => ResultField::Failed,
        }
    }
}

impl From<ResultField> for AuditResult {
    fn from(result: ResultField) -> Self {
        match result {
            ResultField::Ok => AuditResult::Ok,
            ResultField::Failed => AuditResult::Failed,
        }
    }
}

/// A line read back, with the hash it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub record: Record,
    pub hash: String,
}

/// Serializes `record` into a line (without the newline) and returns it with
/// its hash.
pub fn encode(record: &Record) -> Result<(String, String), serde_json::Error> {
    let body = serde_json::to_string(record)?;
    let hash = sha256_hex(body.as_bytes());
    let open = body.strip_suffix('}').unwrap_or(&body);
    Ok((format!("{open}{HASH_PREFIX}{hash}{HASH_SUFFIX}"), hash))
}

/// Parses a line and checks that its content matches its hash.
pub fn decode(line: &str) -> Result<Decoded, BreakKind> {
    let unreadable = |reason: &str| BreakKind::Unreadable {
        reason: reason.to_owned(),
    };
    let split = line
        .len()
        .checked_sub(HASH_PREFIX.len() + HASH_LEN + HASH_SUFFIX.len())
        .filter(|at| line.is_char_boundary(*at))
        .ok_or_else(|| unreadable("too short to hold a hash"))?;
    let (open, tail) = line.split_at(split);
    let hash = tail
        .strip_prefix(HASH_PREFIX)
        .and_then(|t| t.strip_suffix(HASH_SUFFIX))
        .filter(|h| {
            h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| unreadable("it does not end with its hash"))?;
    let body = format!("{open}}}");
    if sha256_hex(body.as_bytes()) != hash {
        return Err(BreakKind::Edited);
    }
    let record: Record = serde_json::from_str(&body).map_err(|e| unreadable(&e.to_string()))?;
    if record.schema_version > SCHEMA_VERSION {
        return Err(unreadable(&format!(
            "schema {} is newer than this enclos ({SCHEMA_VERSION}); upgrade enclos",
            record.schema_version
        )));
    }
    Ok(Decoded {
        record,
        hash: hash.to_owned(),
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(seq: u64, prev: &str) -> Record {
        Record {
            schema_version: SCHEMA_VERSION,
            seq,
            prev: prev.to_owned(),
            at: "2026-01-02T03:04:05Z".parse().unwrap(),
            body: Body::Begin {
                user: "alice".into(),
                host: "mac".into(),
                command: "init".into(),
                target: None,
            },
        }
    }

    #[test]
    fn sha256_of_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let record = begin(1, GENESIS);
        let (line, hash) = encode(&record).unwrap();
        assert!(line.ends_with(&format!(",\"hash\":\"{hash}\"}}")));
        assert!(line.contains("\"kind\":\"begin\""));
        assert_eq!(decode(&line), Ok(Decoded { record, hash }));
    }

    #[test]
    fn finish_records_round_trip() {
        let mut record = begin(2, GENESIS);
        record.body = Body::Finish {
            entry: 1,
            result: ResultField::Failed,
            message: "disk full".into(),
        };
        let (line, _) = encode(&record).unwrap();
        assert!(line.contains("\"result\":\"failed\""));
        assert_eq!(decode(&line).unwrap().record, record);
    }

    #[test]
    fn an_edited_line_fails_its_hash() {
        let (line, _) = encode(&begin(1, GENESIS)).unwrap();
        let edited = line.replace("alice", "mallory");
        assert_eq!(decode(&edited), Err(BreakKind::Edited));
    }

    #[test]
    fn a_line_without_hash_is_unreadable() {
        for line in [
            "",
            "{}",
            "not json at all, but long enough to hold a hash of 64 chars",
        ] {
            assert!(
                matches!(decode(line), Err(BreakKind::Unreadable { .. })),
                "{line}"
            );
        }
    }

    #[test]
    fn a_newer_schema_is_unreadable() {
        let mut record = begin(1, GENESIS);
        record.schema_version = SCHEMA_VERSION + 1;
        let (line, _) = encode(&record).unwrap();
        assert!(matches!(decode(&line), Err(BreakKind::Unreadable { .. })));
    }
}
