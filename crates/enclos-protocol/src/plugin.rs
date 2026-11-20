//! The plugin leg: the bridge and one agent's channel plugin, over a Unix
//! socket in the sandbox home, one JSON object per line
//! (`docs/protocol.md`, The plugin leg).

use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::{DecodeError, Envelope, decode};
use crate::ids::{self, ConversationId, HeldTaskId, MessageId, Person, QuestionId};

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
    #[serde(rename = "question.answer")]
    QuestionAnswer {
        conversation: ConversationId,
        question: QuestionId,
        answer: crate::question::QuestionAnswer,
        /// For a runtime approval, the bridge's signature of the decision
        /// ([`crate::decision`]), which the plugin acts on alone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed: Option<crate::decision::SignedDecision>,
    },
    #[serde(rename = "question.sync")]
    QuestionSync { questions: Vec<QuestionId> },
    /// Resume this held task with the runtime's own operation, only while
    /// it is still held. `revision` is the runtime's, from the plugin's last
    /// `held_tasks`: the plugin refuses (`conflict`) one that is no longer
    /// current when it checks. A live control from the host's person,
    /// never queued: the plugin answers `held_task.resumed` or an `error`.
    #[serde(rename = "held_task.resume")]
    HeldTaskResume {
        task: HeldTaskId,
        revision: crate::ids::HeldTaskRevision,
        /// Who asked, from which of their paired devices, as the bridge
        /// authenticated them.
        person: Person,
        device: String,
    },
    /// The detail of one of the agent's tasks, by the runtime's id
    /// (`task_details`): a read, which the plugin answers `task.detail` or
    /// an `error` (`not_found` for a task that is not the agent's).
    #[serde(rename = "task.get")]
    TaskGet {
        task: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        held: bool,
    },
    #[serde(rename = "routine.request")]
    RoutineRequest {
        /// Current owner-authorized targets, supplied by the bridge rather than the device.
        allowed_deliveries: Vec<ConversationId>,
        /// Who asked, from which of their paired devices (its bridge id), as
        /// the bridge authenticated them: a routine the request creates
        /// keeps both, so the runtime says where it came from.
        person: Person,
        device: String,
        #[serde(flatten)]
        request: Box<crate::routine::RoutineRequest>,
    },
    /// A live request about the agent's model from the host's person
    /// (`model` capability): the plugin answers `model.response` or an
    /// `error`: `conflict` for a stale revision; `not_found` for a model
    /// provider the runtime does not list, or a model it does not list when
    /// it takes no other; `not_allowed` for a model provider the agent
    /// cannot use yet, or a model the runtime refuses; `unsupported` for an
    /// answer too large to send; `agent_unavailable` when the runtime could
    /// not be read and nothing changed; `unknown` when a change may have
    /// been made but was not confirmed.
    #[serde(rename = "model.request")]
    ModelRequest {
        /// Who asked, from which of their paired devices, as the bridge
        /// authenticated them.
        person: Person,
        device: String,
        #[serde(flatten)]
        request: crate::model::ModelRequest,
    },
    /// First on every connection: the agent's token, and its Home
    /// conversation, where what has no conversation of its own goes (the
    /// runtime's home channel: Hermes's cron jobs, `send_message` with no
    /// target).
    #[serde(rename = "hello")]
    Hello {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        home: Option<ConversationId>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<Capability>,
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
        /// Whether `person` is the host's person. It is not signed, so it
        /// grants nothing: the plugin answers every typed approval command
        /// itself, whoever sends it (ADR 0060). An older bridge says nothing
        /// (`None`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<bool>,
        /// The files the person sent with it (ADR 0076, proposed), only to a
        /// plugin that names [`Capability::IncomingFiles`]: their bytes follow
        /// in `message.part`s naming this message's id, and the plugin gives
        /// the runtime the message once it has every byte.
        #[serde(
            default,
            deserialize_with = "crate::incoming::some_files",
            skip_serializing_if = "Vec::is_empty"
        )]
        files: Vec<crate::incoming::IncomingFile>,
        /// The bridge's signature of this message ([`crate::decision`],
        /// `HostMessage`): only on a message the host's person sent from a
        /// paired device in a direct conversation, with no attachments, so
        /// never alongside `files`. A channel may give that turn its
        /// runtime's owner authority, after checking it (ADR 0077, proposed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed: Option<crate::decision::SignedDecision>,
    },
    /// The next bytes of a file of a `message.in` with files.
    #[serde(rename = "message.part")]
    MessagePart(crate::incoming::Part),
    /// Requests cancellation of this exact ingress, when the plugin advertises
    /// `abort`. Unknown or settled targets have no effect on later turns. An ack
    /// accepts the request; it does not certify native cleanup has drained.
    #[serde(rename = "turn.abort")]
    TurnAbort {
        conversation: ConversationId,
        of: MessageId,
    },
    /// The person named the conversation, or, with an empty `title`,
    /// cleared its name.
    #[serde(rename = "conversation.rename")]
    Rename {
        conversation: ConversationId,
        title: String,
    },
    /// Delete this chat through the runtime's session owner; Ack only after completion.
    #[serde(rename = "conversation.delete")]
    Delete { conversation: ConversationId },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The `type`s of [`FromBridge`].
pub const FROM_BRIDGE_TYPES: &[&str] = &[
    "question.answer",
    "question.sync",
    "held_task.resume",
    "task.get",
    "routine.request",
    "model.request",
    "policy.context",
    "hello",
    "message.in",
    "message.part",
    "turn.abort",
    "conversation.rename",
    "conversation.delete",
    "ack",
    "error",
];

/// What a plugin sends to the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromPlugin {
    #[serde(rename = "question.ask")]
    QuestionAsk {
        conversation: ConversationId,
        question: crate::question::QuestionDefinition,
    },
    #[serde(rename = "question.update")]
    QuestionUpdate {
        question: QuestionId,
        state: crate::question::QuestionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answer: Option<crate::question::QuestionAnswer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        of: Option<MessageId>,
    },
    #[serde(rename = "routine.response")]
    RoutineResponse(crate::routine::RoutineReply),
    #[serde(rename = "model.response")]
    ModelResponse(crate::model::ModelReply),
    /// Every task of this agent's runtime held now, whole (at most
    /// [`crate::held_task::MAX_HELD_TASKS`]): after the `hello`, and again
    /// whenever one is held, changes or is no longer held. The bridge
    /// releases the cards of tasks it no longer lists.
    #[serde(rename = "held_tasks")]
    HeldTasks {
        tasks: Vec<crate::held_task::HeldTask>,
    },
    /// The runtime resumed the task a `held_task.resume` named.
    #[serde(rename = "held_task.resumed")]
    HeldTaskResumed { of: MessageId },
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
        #[serde(
            default,
            deserialize_with = "crate::suggested_replies::deserialize",
            skip_serializing_if = "Vec::is_empty"
        )]
        suggested_replies: Vec<String>,
        conversation: ConversationId,
        text: String,
        kind: OutKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<MessageId>,
        /// Files the agent sends with it (an image it made, a document),
        /// each put in the channel's `media` folder first.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<OutAttachment>,
        /// With `kind: task_event`, the task and what happened to it, read
        /// from the runtime's state (ADR 0071, proposed). A bridge keeps the
        /// text alone, as a `notify`, when it is missing or unusable; one
        /// that does not parse reads as missing, so the message is not lost.
        #[serde(
            default,
            deserialize_with = "crate::task_event::lenient",
            skip_serializing_if = "Option::is_none"
        )]
        task_event: Option<crate::task_event::TaskEvent>,
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
    /// What one model call of the agent consumed, or a few: only to a
    /// bridge whose `hello` names [`Capability::Usage`].
    #[serde(rename = "usage")]
    Usage(crate::usage::CallUsage),
    /// What model calls of the agent outside any app conversation consumed:
    /// only to a bridge whose `hello` names [`Capability::AgentUsage`].
    #[serde(rename = "usage.agent")]
    AgentUsage(crate::usage::AgentCallUsage),
    /// The commands a person may type to the runtime (`/new`, `/model`),
    /// whole: after the `hello`, and again when they change.
    #[serde(rename = "commands")]
    Commands { commands: Vec<Command> },
    /// What the agent is doing, whole (`activity`).
    #[serde(rename = "agent.activity")]
    Activity(crate::task::Activity),
    /// One of the agent's tasks, when it changes (`tasks`).
    #[serde(rename = "task.update")]
    TaskUpdate { task: crate::task::Task },
    /// Every task of the agent's the runtime still has (`tasks`).
    #[serde(rename = "tasks")]
    Tasks { tasks: Vec<crate::task::Task> },
    /// The answer to the bridge's `task.get` `of` (`task_details`).
    #[serde(rename = "task.detail")]
    TaskDetail {
        of: MessageId,
        detail: crate::task_detail::TaskDetail,
    },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The `type`s of [`FromPlugin`].
pub const FROM_PLUGIN_TYPES: &[&str] = &[
    "question.ask",
    "question.update",
    "routine.response",
    "model.response",
    "held_tasks",
    "held_task.resumed",
    "hello",
    "approval.request",
    "message.out",
    "typing",
    "conversation.title",
    "tool",
    "usage",
    "usage.agent",
    "commands",
    "agent.activity",
    "task.update",
    "tasks",
    "task.detail",
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
    /// Not the agent speaking but its runtime, about one of its tasks
    /// (Hermes's kanban ping), with `task_event`: shown as a task line.
    /// Sent only to a bridge whose `hello` names
    /// [`Capability::TaskEvents`]; an older one gets it as `notify`.
    TaskEvent,
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
    /// Accepts `turn.abort` for an exact original incoming message id.
    Abort,
    /// It names conversations (`conversation.title`).
    Titles,
    /// It reports the tools it runs while it works (`tool`).
    Tools,
    /// It lists the commands a person may type to it (`commands`).
    Commands,
    Routines,
    Questions,
    RuntimeApprovals,
    /// Independent native approval scopes plus their persistence/fallback
    /// descriptions; extends, rather than replaces, RuntimeApprovals.
    RuntimeApprovalScopes,
    /// It permanently deletes a conversation's native session history.
    ConversationDelete,
    /// It reports its runtime's held tasks and resumes one (`held_tasks`,
    /// `held_task.resume`); requires the bridge's matching hello capability.
    HeldTasks,
    /// It reports what the agent is doing (`agent.activity`).
    Activity,
    /// It reports the agent's tasks (`task.update`, `tasks`).
    Tasks,
    /// It answers `task.get` with one of the agent's tasks' detail
    /// (`task.detail`); requires the bridge's matching hello capability.
    TaskDetails,
    /// It reads details of a held task created by this agent, using its exact board reference.
    HeldTaskDetails,
    /// It reports what each model call of the agent consumed (`usage`); a
    /// bridge that takes them names it in its own `hello`.
    Usage,
    /// It reports the agent's model calls outside app conversations too
    /// (`usage.agent`); a bridge that takes them names it in its `hello`.
    AgentUsage,
    /// It reads and changes the agent's model with the runtime's own
    /// catalogue and setting (`model.request`).
    Model,
    /// It takes the files a person sends with a message (`message.in`'s
    /// `files`, `message.part`), writes them inside its sandbox and gives
    /// them to the runtime with the message (ADR 0076, proposed).
    IncomingFiles,
    /// It sends its runtime's task events as `message.out` of `kind:
    /// task_event`; a bridge that takes them names it in its `hello`, a
    /// device that draws them in its `auth`, and each gets them as `notify`
    /// otherwise (ADR 0071, proposed).
    TaskEvents,
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
    /// What the request changes was changed since the revision it names,
    /// or a request id was reused.
    Conflict,
    /// The receiver failed on its side; trying again later may work.
    Internal,
    Unsupported,
    NotFound,
    /// A request that may have reached the agent, whose outcome was not
    /// confirmed: unlike `agent_unavailable`, retrying is not known to be safe.
    Unconfirmed,
    /// Another provisioning operation is running in this sandbox; nothing changed.
    Busy,
    /// The engine or installer refused or failed; check the sandbox on the host.
    OperationFailed,
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
