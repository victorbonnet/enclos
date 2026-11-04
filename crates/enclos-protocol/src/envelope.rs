//! The fields every message starts with, and the rules for reading one.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ids::MessageId;

/// The protocol's version, the `v` of every message.
pub const VERSION: u32 = 1;

/// Largest message, in bytes, either way.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// A message: its version, its id, and its body, whose `type` field says
/// which message it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<B> {
    pub v: u32,
    pub id: MessageId,
    #[serde(flatten)]
    pub body: B,
}

impl<B> Envelope<B> {
    /// A message of this version.
    pub fn new(id: MessageId, body: B) -> Self {
        Self {
            v: VERSION,
            id,
            body,
        }
    }
}

/// Why bytes were not a message the receiver can act on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("message is larger than 1 MiB")]
    TooBig,
    #[error("not a JSON object: {0}")]
    NotJson(String),
    #[error("version {0} is not spoken here")]
    Version(u64),
    /// A `type` this receiver does not know: answer `unknown_type` and go on,
    /// since a newer peer may send optional messages.
    #[error("unknown type {kind:?}")]
    UnknownType { id: Option<String>, kind: String },
    /// A known `type` whose fields are wrong or missing: answer
    /// `bad_message`.
    #[error("bad message: {reason}")]
    Bad { id: Option<String>, reason: String },
}

/// Reads one message. `known` lists the `type`s the body accepts, so an
/// unknown one is told apart from a known one with bad fields.
pub fn decode<B: DeserializeOwned>(
    bytes: &[u8],
    known: &[&str],
) -> Result<Envelope<B>, DecodeError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DecodeError::TooBig);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| DecodeError::NotJson(e.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| DecodeError::NotJson("not an object".to_owned()))?;
    let id = object
        .get("id")
        .and_then(|id| id.as_str())
        .map(str::to_owned);
    match object.get("v").and_then(serde_json::Value::as_u64) {
        Some(v) if v == u64::from(VERSION) => {}
        Some(v) => return Err(DecodeError::Version(v)),
        None => {
            return Err(DecodeError::Bad {
                id,
                reason: "no version".to_owned(),
            });
        }
    }
    let Some(kind) = object.get("type").and_then(|t| t.as_str()) else {
        return Err(DecodeError::Bad {
            id,
            reason: "no type".to_owned(),
        });
    };
    if !known.contains(&kind) {
        return Err(DecodeError::UnknownType {
            id,
            kind: kind.to_owned(),
        });
    }
    serde_json::from_value(value).map_err(|e| DecodeError::Bad {
        id,
        reason: e.to_string(),
    })
}

/// Writes one message as a line of JSON: compact, so no line break inside,
/// and ending with one.
pub fn encode_line<B: Serialize>(message: &Envelope<B>) -> Vec<u8> {
    let mut line = serde_json::to_vec(message).expect("a protocol message always serializes");
    line.push(b'\n');
    line
}
