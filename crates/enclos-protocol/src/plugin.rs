//! The plugin leg: the bridge and one agent's channel plugin, over a Unix
//! socket in the sandbox home, one JSON object per line
//! (`docs/protocol.md`, The plugin leg).

use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::{DecodeError, Envelope, decode};
use crate::ids::{self, ConversationId, MessageId, Person};

/// A name the sandbox sends, which the host may print: the id rule.
fn name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    ids::check(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

/// Text for people, which the host may print: no control character, so it
/// cannot move a terminal's cursor or break a log's line.
fn line<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.chars().any(char::is_control) {
        return Err(serde::de::Error::custom("holds a control character"));
    }
    Ok(value)
}

/// What the bridge sends to a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromBridge {
    /// First on every connection: the agent's token.
    #[serde(rename = "hello")]
    Hello { token: String },
    /// A person's message to the agent.
    #[serde(rename = "message.in")]
    MessageIn {
        conversation: ConversationId,
        person: Person,
        text: String,
    },
    /// The person named the conversation, or, with an empty `title`,
    /// cleared its name.
    #[serde(rename = "conversation.rename")]
    Rename {
        conversation: ConversationId,
        title: String,
    },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The `type`s of [`FromBridge`].
pub const FROM_BRIDGE_TYPES: &[&str] =
    &["hello", "message.in", "conversation.rename", "ack", "error"];

/// What a plugin sends to the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromPlugin {
    /// The plugin's answer to the bridge's `hello`.
    #[serde(rename = "hello")]
    Hello {
        /// The runtime's name (`hermes`), by the id rule.
        #[serde(deserialize_with = "name")]
        runtime: String,
        /// The agent's name in its runtime (`main`), by the id rule.
        #[serde(deserialize_with = "name")]
        agent: String,
        capabilities: Vec<Capability>,
    },
    /// What the agent says.
    #[serde(rename = "message.out")]
    MessageOut {
        conversation: ConversationId,
        text: String,
        kind: OutKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<MessageId>,
    },
    /// The agent is, or stops, working on an answer.
    #[serde(rename = "typing")]
    Typing {
        conversation: ConversationId,
        on: bool,
    },
    /// A short name for the conversation, from what was said in it: the
    /// runtime's own (Hermes: its session title). The bridge keeps a name
    /// the person gave over it.
    #[serde(rename = "conversation.title")]
    Title {
        conversation: ConversationId,
        title: String,
    },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The `type`s of [`FromPlugin`].
pub const FROM_PLUGIN_TYPES: &[&str] = &[
    "hello",
    "message.out",
    "typing",
    "conversation.title",
    "ack",
    "error",
];

/// Whether an agent's message answers one, or comes on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutKind {
    Reply,
    /// Sent with nobody asking now: a cron job, background work.
    Notify,
}

/// What a runtime can do; an unknown one, from a newer plugin, reads as
/// `Unknown` and is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Notify,
    Typing,
    Stream,
    Attachments,
    Approval,
    Abort,
    /// It names conversations (`conversation.title`).
    Titles,
    #[serde(other)]
    Unknown,
}

/// The body of an `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub of: Option<MessageId>,
    pub code: ErrorCode,
    /// For people, may be shown: one line, no control character.
    #[serde(deserialize_with = "line")]
    pub message: String,
}

/// `docs/protocol.md`, Errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownType,
    BadMessage,
    Version,
    NotAllowed,
    UnknownAgent,
    UnknownConversation,
    AgentUnavailable,
    #[serde(other)]
    Unknown,
}

/// Reads a message the bridge sent.
pub fn decode_from_bridge(line: &[u8]) -> Result<Envelope<FromBridge>, DecodeError> {
    decode(line, FROM_BRIDGE_TYPES)
}

/// Reads a message a plugin sent.
pub fn decode_from_plugin(line: &[u8]) -> Result<Envelope<FromPlugin>, DecodeError> {
    decode(line, FROM_PLUGIN_TYPES)
}
