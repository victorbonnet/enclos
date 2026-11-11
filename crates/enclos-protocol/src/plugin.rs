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
    /// First on every connection: the agent's token, and its Home
    /// conversation, where what has no conversation of its own goes (the
    /// runtime's home channel: Hermes's cron jobs, `send_message` with no
    /// target).
    #[serde(rename = "hello")]
    Hello {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        home: Option<ConversationId>,
    },
    /// Current active grants, refreshed at connect and after a policy decision.
    #[serde(rename = "policy.context")]
    PolicyContext { text: String },
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
pub const FROM_BRIDGE_TYPES: &[&str] = &[
    "policy.context",
    "hello",
    "message.in",
    "conversation.rename",
    "ack",
    "error",
];

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
    /// An attempted action the sandbox refused, or a request before trying it.
    #[serde(rename = "approval.request")]
    ApprovalRequest {
        conversation: ConversationId,
        access: crate::approval::Access,
        action: String,
    },
    /// What the agent says.
    #[serde(rename = "message.out")]
    MessageOut {
        conversation: ConversationId,
        text: String,
        kind: OutKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<MessageId>,
        /// Files the agent sends with it (an image it made, a document),
        /// each put in the channel's `media` folder first.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<OutAttachment>,
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
    /// A step of the agent's work on an answer: a tool it starts, or ends.
    #[serde(rename = "tool")]
    Tool(ToolStep),
    /// The commands a person may type to the runtime (`/new`, `/model`),
    /// whole: after the `hello`, and again when they change.
    #[serde(rename = "commands")]
    Commands { commands: Vec<Command> },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The `type`s of [`FromPlugin`].
pub const FROM_PLUGIN_TYPES: &[&str] = &[
    "hello",
    "approval.request",
    "message.out",
    "typing",
    "conversation.title",
    "tool",
    "commands",
    "ack",
    "error",
];

/// A command the person may type to the runtime: `/` and its name, then
/// what `args` says, if anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// Without the `/`: `new`, `model`.
    pub name: String,
    /// What it does, one line.
    #[serde(default)]
    pub description: String,
    /// What follows it, as the runtime writes it (`[name]`, `<prompt>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
}

/// A file the agent sends, which the plugin put in the channel's `media`
/// folder (beside its socket, in the sandbox home): the bridge takes it from
/// there, by its name alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutAttachment {
    /// Its name in the `media` folder: no folder, no `..`.
    pub file: String,
    /// Its media type (`image/png`, `application/pdf`).
    pub mime: String,
    /// The name to show and to share it as.
    pub name: String,
    pub size: u64,
}

/// One tool the agent runs while it works on an answer, as the plugin
/// reports it and the bridge passes it on: shown live, not stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStep {
    pub conversation: ConversationId,
    /// The runtime's id of this call, the same at its start and its end.
    pub call: String,
    /// The tool, as the runtime names it (`terminal`, `web_search`).
    pub name: String,
    /// A short line about what it does (`ls -la`, `weather Lyon`), at its start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub phase: ToolPhase,
    /// At its end: whether it worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// At its end: how long it took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Whether a [`ToolStep`] starts or ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPhase {
    Start,
    End,
}

/// Whether an agent's message answers one, or comes on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutKind {
    Reply,
    /// Sent with nobody asking now: a cron job, background work.
    Notify,
    /// Not the agent speaking but its runtime, about itself: Hermes's
    /// gateway going online or shutting down. Shown as a quiet line.
    Status,
}

/// What a runtime can do; an unknown one, from a newer plugin, reads as
/// `Unknown` and is ignored. Sending on its own (`kind: notify`) is not
/// one: every runtime may. `notify`, which older plugins announce, reads
/// as `Unknown` too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Typing,
    Stream,
    Attachments,
    Approval,
    Abort,
    /// It names conversations (`conversation.title`).
    Titles,
    /// It reports the tools it runs while it works (`tool`).
    Tools,
    /// It lists the commands a person may type to it (`commands`).
    Commands,
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
    /// What the request changes was changed since the revision it names.
    Conflict,
    /// The receiver failed on its side; trying again later may work.
    Internal,
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
