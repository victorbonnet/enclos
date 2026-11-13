//! The device leg's messages (`docs/protocol.md`, Messages after the
//! handshake), each inside a Noise transport message. Bytes travel as
//! base64url text ([`crate::pairing::encode`]).

use serde::{Deserialize, Serialize};

use crate::envelope::{DecodeError, Envelope, decode, encode_line};
use crate::ids::{ConversationId, MAX_ID_BYTES, MessageId, QuestionId};
use crate::noise::MAX_NOISE_MESSAGE;
use crate::plugin::{Capability, Command, ErrorBody, ToolStep};

/// What a device sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromDevice {
    #[serde(rename = "question.answer")]
    QuestionAnswer {
        question: QuestionId,
        revision: u64,
        answer: crate::question::QuestionAnswer,
    },
    #[serde(rename = "agent.name.get")]
    AgentNameGet { agent: String },
    #[serde(rename = "agent.name.set")]
    AgentNameSet(crate::agent_name::NameSet),
    #[serde(rename = "routine.request")]
    RoutineRequest {
        agent: String,
        #[serde(flatten)]
        request: crate::routine::RoutineRequest,
    },
    #[serde(rename = "agent.avatar.get")]
    AgentAvatarGet { agent: String },
    #[serde(rename = "agent.avatar.set")]
    AgentAvatarSet(crate::avatar::AvatarSet),
    #[serde(rename = "sandbox.policy.get")]
    SandboxPolicyGet { sandbox: String },
    #[serde(rename = "sandbox.policy.preview")]
    SandboxPolicyPreview {
        sandbox: String,
        base: String,
        change: crate::policy::PolicyChange,
    },
    #[serde(rename = "sandbox.policy.apply")]
    SandboxPolicyApply {
        sandbox: String,
        #[serde(flatten)]
        edit: crate::policy::PolicyApply,
    },
    /// First after the handshake of a paired device: its id on this host
    /// and its hardware key's DER signature of the handshake hash for
    /// `auth` ([`crate::pairing::Signed::Auth`]).
    #[serde(rename = "auth")]
    Auth { device: String, sig: String },
    /// First after the handshake of a device that is pairing.
    #[serde(rename = "pair.request")]
    PairRequest {
        name: String,
        /// Its P-256 public key, SEC1.
        device_key: String,
        /// HMAC-SHA256 of the handshake hash, keyed with the code.
        proof: String,
        /// Its hardware key's DER signature of the handshake hash for
        /// pairing ([`crate::pairing::Signed::Pair`]): it holds the key it
        /// asks to pair.
        sig: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        push: Option<PushToken>,
    },
    #[serde(rename = "approval.decide")]
    ApprovalDecide {
        request: String,
        revision: String,
        approve: bool,
    },
    #[serde(rename = "audit")]
    Audit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before: Option<u64>,
    },
    #[serde(rename = "agents")]
    Agents,
    #[serde(rename = "sandboxes")]
    Sandboxes,
    #[serde(rename = "runtimes")]
    Runtimes,
    #[serde(rename = "sandbox.create")]
    SandboxCreate { sandbox: String, template: String },
    #[serde(rename = "runtime.install")]
    RuntimeInstall { sandbox: String, runtime: String },
    #[serde(rename = "conversation.new")]
    ConversationNew {
        conversation: ConversationId,
        agent: String,
    },
    /// Starts a group with two to six agents of one sandbox.
    #[serde(rename = "group.new")]
    GroupNew {
        conversation: ConversationId,
        /// `<sandbox>/<agent>` each.
        members: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    /// Stops a group's discussion; what was said stays.
    #[serde(rename = "group.stop")]
    GroupStop { conversation: ConversationId },
    #[serde(rename = "message.send")]
    MessageSend {
        conversation: ConversationId,
        text: String,
    },
    /// Names the conversation; an empty `title` clears the name, and the
    /// runtime may name it again.
    #[serde(rename = "conversation.rename")]
    ConversationRename {
        conversation: ConversationId,
        title: String,
    },
    /// The person read the conversation up to message `seq`, on this
    /// device: the bridge keeps it, for their other devices and the next.
    #[serde(rename = "conversation.read")]
    ConversationRead {
        conversation: ConversationId,
        seq: i64,
    },
    /// Changes only whether the owner's conversation appears in active lists.
    #[serde(rename = "conversation.archive")]
    ConversationArchive {
        conversation: ConversationId,
        archived: bool,
    },
    /// Permanently deletes an owned conversation and its runtime sessions.
    #[serde(rename = "conversation.delete")]
    ConversationDelete { conversation: ConversationId },
    /// The bytes of an attachment of one of the person's messages, from
    /// `offset`: the bridge answers with one `attachment.data`.
    #[serde(rename = "attachment.get")]
    AttachmentGet { attachment: String, offset: u64 },
    #[serde(rename = "sync")]
    Sync { since: i64 },
    #[serde(rename = "push.token")]
    PushTokenUpdate(PushToken),
    /// The person forgets this host on the device: the bridge unpairs the
    /// device, acknowledges, and ends the connection.
    #[serde(rename = "device.forget")]
    DeviceForget,
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

pub const FROM_DEVICE_TYPES: &[&str] = &[
    "question.answer",
    "agent.name.get",
    "agent.name.set",
    "routine.request",
    "agent.avatar.get",
    "agent.avatar.set",
    "sandbox.policy.get",
    "sandbox.policy.preview",
    "sandbox.policy.apply",
    "auth",
    "pair.request",
    "approval.decide",
    "agents",
    "sandboxes",
    "runtimes",
    "sandbox.create",
    "runtime.install",
    "audit",
    "conversation.new",
    "group.new",
    "group.stop",
    "message.send",
    "conversation.rename",
    "conversation.read",
    "conversation.archive",
    "conversation.delete",
    "attachment.get",
    "sync",
    "push.token",
    "device.forget",
    "ack",
    "error",
];

/// What the bridge sends a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToDevice {
    #[serde(rename = "question")]
    Question {
        question: crate::question::QuestionInfo,
    },
    #[serde(rename = "question.result")]
    QuestionResult {
        of: MessageId,
        question: crate::question::QuestionInfo,
    },
    #[serde(rename = "agent.name")]
    AgentName(crate::agent_name::AgentName),
    #[serde(rename = "routine.response")]
    RoutineResponse {
        agent: String,
        #[serde(flatten)]
        reply: crate::routine::RoutineReply,
    },
    #[serde(rename = "agent.avatar")]
    AgentAvatar(crate::avatar::AgentAvatar),
    #[serde(rename = "sandbox.policy")]
    SandboxPolicy(crate::policy::PolicyState),
    #[serde(rename = "sandbox.policy.preview")]
    SandboxPolicyPreview(crate::policy::PolicyPreview),
    #[serde(rename = "approval")]
    Approval(crate::approval::Approval),
    /// The device is known and its signature holds: who it speaks for.
    #[serde(rename = "authenticated")]
    Authenticated {
        person: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },

    #[serde(rename = "audit.list")]
    AuditList {
        of: MessageId,
        entries: Vec<AuditEntryInfo>,
        next_before: Option<u64>,
    },
    #[serde(rename = "pair.accepted")]
    PairAccepted { device: String, push_key: String },
    #[serde(rename = "pair.refused")]
    PairRefused { reason: String },
    #[serde(rename = "agents.list")]
    AgentsList { agents: Vec<AgentInfo> },
    #[serde(rename = "sandboxes.list")]
    SandboxesList { sandboxes: Vec<SandboxInfo> },
    #[serde(rename = "runtimes.list")]
    RuntimesList { runtimes: Vec<RuntimeInfo> },
    #[serde(rename = "operation.progress")]
    OperationProgress {
        of: MessageId,
        operation: String,
        sandbox: String,
        message: String,
    },
    #[serde(rename = "sandbox.created")]
    SandboxCreated { of: MessageId, sandbox: String },
    #[serde(rename = "runtime.installed")]
    RuntimeInstalled {
        of: MessageId,
        sandbox: String,
        runtime: String,
        login: String,
    },
    /// A permanent deletion, repeated at sync even when there are no new messages.
    #[serde(rename = "conversation.deleted")]
    ConversationDeleted { conversation: ConversationId },
    /// One of the person's conversations: each at `sync`, before the
    /// messages, and again whenever its name, read position or archive state changes.
    #[serde(rename = "conversation")]
    Conversation(ConversationInfo),
    #[serde(rename = "message")]
    Message(ConversationMessage),
    #[serde(rename = "typing")]
    Typing {
        conversation: ConversationId,
        on: bool,
    },
    /// A tool the agent starts or ends while it works: as on the plugin
    /// leg, live, not kept.
    #[serde(rename = "tool")]
    Tool(ToolStep),
    /// The commands a person may type to an agent's runtime, whole, as its
    /// plugin listed them ([`commands_for_devices`]): after `agents.list`,
    /// and again when they change.
    /// Where a group's discussion is: at `sync` and whenever it changes.
    #[serde(rename = "group.state")]
    GroupState(GroupState),
    #[serde(rename = "commands")]
    Commands {
        /// `<sandbox>/<agent>`.
        agent: String,
        commands: Vec<Command>,
    },
    /// Bytes of an attachment, from `offset`, at most [`ATTACHMENT_CHUNK`]:
    /// a Noise message holds 64 KiB, base64 included.
    #[serde(rename = "attachment.data")]
    AttachmentData {
        attachment: String,
        offset: u64,
        /// The whole attachment's size.
        size: u64,
        /// base64url.
        data: String,
    },
    #[serde(rename = "synced")]
    Synced { seq: i64 },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

/// The most bytes of an attachment one `attachment.data` carries: base64
/// makes 60,000 characters of them, inside a Noise message's 65,519.
pub const ATTACHMENT_CHUNK: usize = 45_000;

pub const TO_DEVICE_TYPES: &[&str] = &[
    "question",
    "question.result",
    "agent.name",
    "routine.response",
    "agent.avatar",
    "sandbox.policy",
    "sandbox.policy.preview",
    "approval",
    "authenticated",
    "audit.list",
    "pair.accepted",
    "pair.refused",
    "agents.list",
    "sandboxes.list",
    "runtimes.list",
    "operation.progress",
    "sandbox.created",
    "runtime.installed",
    "conversation",
    "conversation.deleted",
    "message",
    "typing",
    "tool",
    "commands",
    "group.state",
    "attachment.data",
    "synced",
    "ack",
    "error",
];

/// The longest command name passed on, as Telegram and Discord allow.
pub const MAX_COMMAND_NAME: usize = 32;
/// The longest description passed on, in characters: a line on a phone.
pub const MAX_COMMAND_DESCRIPTION: usize = 120;
/// The longest `args` passed on, in characters.
pub const MAX_COMMAND_ARGS: usize = 60;
/// The most bytes the commands of one `commands` take: the rest of the
/// message, and the Noise tag, fit in a Noise message's 65,519.
pub const COMMANDS_BUDGET: usize = 60_000;

/// A plugin's commands as a device gets them: each name once (lower case
/// letters, digits, `_` and `-`, at most [`MAX_COMMAND_NAME`]; others are
/// left out), each text on one line, without hidden characters
/// ([`crate::visible`]) and cut to its limit, in the plugin's order until
/// they fill [`COMMANDS_BUDGET`].
pub fn commands_for_devices(commands: Vec<Command>) -> Vec<Command> {
    fn words(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    // A bidirectional override or a zero-width character would make the
    // text beside a command read as something else than what was sent.
    fn line(text: &str, limit: usize) -> String {
        let shown = words(&crate::visible::stripped(&words(text), false));
        let cut: String = shown.chars().take(limit).collect();
        // A cut may leave a joiner at the end, where it is hidden.
        crate::visible::stripped(cut.trim_end(), false)
    }
    let mut seen = std::collections::HashSet::new();
    let mut used = 0;
    let mut kept = Vec::new();
    for c in commands {
        let name = c.name.trim_start_matches('/');
        let valid = !name.is_empty()
            && name.len() <= MAX_COMMAND_NAME
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !valid || !seen.insert(name.to_owned()) {
            continue;
        }
        let command = Command {
            name: name.to_owned(),
            description: line(&c.description, MAX_COMMAND_DESCRIPTION),
            args: c
                .args
                .map(|a| line(&a, MAX_COMMAND_ARGS))
                .filter(|a| !a.is_empty()),
        };
        // Its JSON and the comma before the next.
        let size = serde_json::to_vec(&command).map_or(usize::MAX, |b| b.len() + 1);
        if used + size > COMMANDS_BUDGET {
            break;
        }
        used += size;
        kept.push(command);
    }
    kept
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken {
    pub kind: String,
    pub token: String,
}

/// A state-changing host command, for the audit view shown to the host's person. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntryInfo {
    pub seq: u64,
    pub time: i64,
    pub user: String,
    pub host: String,
    pub command: String,
    pub target: Option<String>,
    /// `ok`, `failed`, or `unfinished` when no outcome was recorded.
    pub result: String,
    pub message: Option<String>,
    pub finished: Option<i64>,
}

/// An agent a person may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Shared presentation only: never the routing address in `agent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub name_revision: u64,
    /// Always sent by new hosts; its presence advertises shared-name support.
    #[serde(default)]
    pub can_edit_name: bool,
    #[serde(
        default,
        skip_serializing_if = "crate::avatar::AvatarMetadata::is_default"
    )]
    pub avatar: crate::avatar::AvatarMetadata,
    #[serde(default)]
    pub can_edit_avatar: bool,
    /// Whether this person may manage the agent's routines: the host's
    /// person only. Absent (an older host) means no.
    #[serde(default)]
    pub can_manage_routines: bool,
    /// `<sandbox>/<agent>`.
    pub agent: String,
    pub runtime: String,
    pub capabilities: Vec<Capability>,
    pub abilities: Vec<String>,
}

/// A conversation: its agent, its name when it has one, and how far the
/// person read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationInfo {
    pub conversation: ConversationId,
    /// `<sandbox>/<agent>`.
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Who named it: `agent` (its runtime), or `person`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub titled_by: Option<String>,
    /// The `seq` of the last message the person read, on any of their
    /// devices; none before they read any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<i64>,
    /// Hidden from active lists until the person explicitly unarchives it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub archived: bool,
    /// Orders this conversation's metadata independently of message `seq`.
    #[serde(default, skip_serializing_if = "revision_is_zero")]
    pub revision: u64,
    /// The agent's Home: where what has no conversation of its own goes
    /// (cron jobs, the runtime's notices). Shown first when active, even empty.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub home: bool,
    /// A group's members, `<sandbox>/<agent>` each, in its order; none for
    /// a conversation with one agent. A group's `agent` is its sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

fn revision_is_zero(revision: &u64) -> bool {
    *revision == 0
}

/// Where a group's discussion is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState {
    pub conversation: ConversationId,
    /// `working`, `settled`, `bounded`, `stopped` or `failed`.
    pub state: String,
    /// The round running, from 0, and how many a discussion may have.
    pub round: u32,
    pub max_rounds: u32,
    /// Each member and its turn in this discussion.
    pub members: Vec<MemberTurn>,
    /// Why it ended, when it did not settle (`max_rounds`, `max_replies`,
    /// a turn's error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A member of a group and its turn: `queued`, `working`, `replied`,
/// `passed`, `failed`, `cancelled`, or none yet in this discussion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberTurn {
    /// `<sandbox>/<agent>`.
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<String>,
}

/// A sandbox on the owner's host, including one with no runtime or app channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub sandbox: String,
    pub runtime: Option<String>,
    pub state: String,
}

/// A runtime this host can install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub runtime: String,
    pub name: String,
    pub description: String,
}

/// One message of a conversation, sent or received alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub conversation: ConversationId,
    pub agent: String,
    /// `agent`, or the person who wrote it.
    pub from: String,
    pub text: String,
    /// `message` for a person's, `reply` or `notify` for the agent's.
    pub kind: String,
    /// Seconds since the Unix epoch.
    pub time: i64,
    pub seq: i64,
    /// Metadata arrives in a separate `question` frame before this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<QuestionId>,
    /// Its files, which the device fetches with `attachment.get`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

/// A file of a message, as a device sees it before fetching it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// The bridge's id for it.
    pub id: String,
    pub mime: String,
    pub name: String,
    pub size: u64,
}

/// The most a message on the device leg may be, as it is sealed: its JSON
/// and the line break after it. A Noise transport message holds 65,535
/// bytes, its 16-byte tag included, and the protocol does not fragment.
pub const MAX_DEVICE_MESSAGE: usize = MAX_NOISE_MESSAGE - 16;

/// Room for any id and `seq`, beyond those the envelope is measured with.
const ID_AND_SEQ_ROOM: usize = MAX_ID_BYTES + 20;

/// `message`'s text in pieces, cut at character boundaries, each of which
/// fits on the device leg as the text of a `message` like this one,
/// whatever its id and `seq`: the bridge sends an agent's long text as
/// consecutive messages. One piece when it fits already.
pub fn split_text(message: &ConversationMessage) -> Vec<String> {
    let empty = ConversationMessage {
        text: String::new(),
        seq: 0,
        ..message.clone()
    };
    let id = MessageId::new("m").expect("a valid id");
    let around = encode_line(&Envelope::new(id, ToDevice::Message(empty))).len();
    let room = MAX_DEVICE_MESSAGE.saturating_sub(around + ID_AND_SEQ_ROOM);
    let escaped = |text: &str| serde_json::to_string(text).map_or(0, |json| json.len() - 2);
    if escaped(&message.text) <= room {
        return vec![message.text.clone()];
    }
    let mut pieces = Vec::new();
    let mut piece = String::new();
    let mut size = 0;
    let mut buffer = [0u8; 4];
    for character in message.text.chars() {
        let length = escaped(character.encode_utf8(&mut buffer));
        if size + length > room && !piece.is_empty() {
            pieces.push(std::mem::take(&mut piece));
            size = 0;
        }
        piece.push(character);
        size += length;
    }
    pieces.push(piece);
    pieces
}

pub fn decode_from_device(bytes: &[u8]) -> Result<Envelope<FromDevice>, DecodeError> {
    decode(bytes, FROM_DEVICE_TYPES)
}

pub fn decode_to_device(bytes: &[u8]) -> Result<Envelope<ToDevice>, DecodeError> {
    decode(bytes, TO_DEVICE_TYPES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_text(text: &str) -> ConversationMessage {
        ConversationMessage {
            question: None,
            conversation: ConversationId::new("c-1").unwrap(),
            agent: "lab/main".into(),
            from: "agent".into(),
            text: text.into(),
            kind: "reply".into(),
            time: 1_700_000_000,
            seq: 1,
            attachments: Vec::new(),
        }
    }

    /// The largest the piece's envelope can be: the longest id, the
    /// widest `seq`.
    fn sealed_size(message: &ConversationMessage, text: &str) -> usize {
        let id = MessageId::new("i".repeat(MAX_ID_BYTES)).unwrap();
        let piece = ConversationMessage {
            text: text.into(),
            seq: i64::MIN,
            ..message.clone()
        };
        encode_line(&Envelope::new(id, ToDevice::Message(piece))).len()
    }

    #[test]
    fn a_text_that_fits_stays_whole() {
        let message = agent_text("hello");
        assert_eq!(split_text(&message), ["hello"]);
    }

    #[test]
    fn a_long_text_is_cut_into_pieces_that_each_fit() {
        // Characters of one to four bytes, and some JSON escapes to six
        let text: String = "aé€😀\"\u{1}\n".repeat(20_000);
        let message = agent_text(&text);
        let pieces = split_text(&message);
        assert!(pieces.len() > 1);
        assert_eq!(pieces.concat(), text);
        for piece in &pieces {
            assert!(sealed_size(&message, piece) <= MAX_DEVICE_MESSAGE);
        }
        // Nearly full: no piece but the last is left far below the limit
        let first = sealed_size(&message, &pieces[0]);
        assert!(first > MAX_DEVICE_MESSAGE - ID_AND_SEQ_ROOM - 8, "{first}");
    }

    fn command(name: &str, description: &str, args: Option<&str>) -> Command {
        Command {
            name: name.into(),
            description: description.into(),
            args: args.map(Into::into),
        }
    }

    #[test]
    fn commands_keep_valid_names_once_each_on_one_line() {
        let kept = commands_for_devices(vec![
            command("new", "Start a new\n  session", Some("[name]")),
            command("/model", "Switch model", Some("  ")),
            command("new", "again", None),
            command("Bad Name", "spaces and capitals", None),
            command("", "empty", None),
            command(&"x".repeat(33), "too long", None),
            command("reload_mcp", &"d".repeat(200), None),
            command(
                "usage",
                "Show\u{202E}tsoc \u{2066}usage\u{2069}\u{200B} \u{1b}[31m",
                Some("[\u{2028}days\u{0}]"),
            ),
            command("tools", "\u{202E}\u{200B}", Some("\u{2067}")),
        ]);
        assert_eq!(
            kept,
            [
                command("new", "Start a new session", Some("[name]")),
                command("model", "Switch model", None),
                command("reload_mcp", &"d".repeat(MAX_COMMAND_DESCRIPTION), None),
                command("usage", "Showtsoc usage [31m", Some("[ days]")),
                command("tools", "", None),
            ]
        );
    }

    #[test]
    fn commands_stop_where_a_message_would_not_fit_a_noise_message() {
        let many = (0..2_000)
            .map(|i| {
                command(
                    &format!("c{i}"),
                    &"é".repeat(MAX_COMMAND_DESCRIPTION),
                    Some("[x]"),
                )
            })
            .collect();
        let kept = commands_for_devices(many);
        assert!(!kept.is_empty() && kept.len() < 2_000);
        let line = encode_line(&Envelope::new(
            MessageId::new("m-1").unwrap(),
            ToDevice::Commands {
                agent: "lab/main".into(),
                commands: kept,
            },
        ));
        assert!(line.len() < 65_519 - 16, "{} bytes", line.len());
    }

    #[test]
    fn device_messages_round_trip() {
        let id = || MessageId::new("m-1").unwrap();
        for body in [
            FromDevice::Auth {
                device: "d1".into(),
                sig: "c2ln".into(),
            },
            FromDevice::Agents,
            FromDevice::Audit { before: None },
            FromDevice::Audit { before: Some(42) },
            FromDevice::MessageSend {
                conversation: ConversationId::new("c-1").unwrap(),
                text: "hi".into(),
            },
            FromDevice::Sync { since: 4 },
            FromDevice::GroupNew {
                conversation: ConversationId::new("g-1").unwrap(),
                members: vec!["lab/main".into(), "lab/coder".into()],
                title: None,
            },
            FromDevice::GroupStop {
                conversation: ConversationId::new("g-1").unwrap(),
            },
            FromDevice::ConversationRead {
                conversation: ConversationId::new("c-1").unwrap(),
                seq: 7,
            },
            FromDevice::DeviceForget,
            FromDevice::AttachmentGet {
                attachment: "a-1".into(),
                offset: 45_000,
            },
            FromDevice::PairRequest {
                name: "Pixel".into(),
                device_key: "a2V5".into(),
                proof: "cHJvb2Y".into(),
                sig: "c2ln".into(),
                push: None,
            },
        ] {
            let line = encode_line(&Envelope::new(id(), body.clone()));
            assert_eq!(decode_from_device(&line).unwrap().body, body);
        }
        // A pairing request must carry the device key's signature.
        let unsigned = br#"{"v":1,"id":"m","type":"pair.request","name":"Pixel","device_key":"a2V5","proof":"cHJvb2Y"}"#;
        assert!(matches!(
            decode_from_device(unsigned),
            Err(DecodeError::Bad { .. })
        ));
        let body = ToDevice::Message(ConversationMessage {
            conversation: ConversationId::new("c-1").unwrap(),
            agent: "lab/main".into(),
            from: "agent".into(),
            text: "hello".into(),
            kind: "reply".into(),
            time: 1_800_000_000,
            seq: 7,
            question: None,
            attachments: vec![Attachment {
                id: "a-1".into(),
                mime: "image/png".into(),
                name: "unicorn.png".into(),
                size: 1_962_976,
            }],
        });
        let line = encode_line(&Envelope::new(id(), body.clone()));
        assert_eq!(decode_to_device(&line).unwrap().body, body);
        let body = ToDevice::Conversation(ConversationInfo {
            conversation: ConversationId::new("c-1").unwrap(),
            agent: "lab/main".into(),
            title: Some("Weather in Lyon".into()),
            titled_by: Some("agent".into()),
            read: Some(7),
            archived: false,
            revision: 0,
            home: false,
            members: Vec::new(),
        });
        let line = encode_line(&Envelope::new(id(), body.clone()));
        assert_eq!(decode_to_device(&line).unwrap().body, body);
        // Only Home says so.
        assert!(!String::from_utf8_lossy(&line).contains("home"));
        let home = ToDevice::Conversation(ConversationInfo {
            conversation: ConversationId::new("home.lab.main").unwrap(),
            agent: "lab/main".into(),
            title: Some("Home".into()),
            titled_by: Some("person".into()),
            read: None,
            archived: false,
            revision: 0,
            home: true,
            members: Vec::new(),
        });
        let line = encode_line(&Envelope::new(id(), home.clone()));
        assert_eq!(decode_to_device(&line).unwrap().body, home);
        // A group: its sandbox, its members, and where its discussion is.
        let group = ToDevice::Conversation(ConversationInfo {
            conversation: ConversationId::new("g-1").unwrap(),
            agent: "lab".into(),
            title: Some("Launch".into()),
            titled_by: Some("person".into()),
            read: None,
            archived: false,
            revision: 0,
            home: false,
            members: vec!["lab/main".into(), "lab/coder".into()],
        });
        let line = encode_line(&Envelope::new(id(), group.clone()));
        assert!(String::from_utf8_lossy(&line).contains(r#""members":["lab/main","lab/coder"]"#));
        assert_eq!(decode_to_device(&line).unwrap().body, group);
        let state = ToDevice::GroupState(GroupState {
            conversation: ConversationId::new("g-1").unwrap(),
            state: "working".into(),
            round: 0,
            max_rounds: 3,
            members: vec![
                MemberTurn {
                    agent: "lab/main".into(),
                    turn: Some("replied".into()),
                },
                MemberTurn {
                    agent: "lab/coder".into(),
                    turn: Some("working".into()),
                },
            ],
            reason: None,
        });
        let line = encode_line(&Envelope::new(id(), state.clone()));
        assert_eq!(decode_to_device(&line).unwrap().body, state);
        let line = encode_line(&Envelope::new(id(), home.clone()));
        assert!(String::from_utf8_lossy(&line).contains(r#""home":true"#));
        assert_eq!(decode_to_device(&line).unwrap().body, home);
        // A conversation never read carries no `read`, and is no Home.
        let unread =
            br#"{"v":1,"id":"m","type":"conversation","conversation":"c-1","agent":"lab/main"}"#;
        assert!(matches!(
            decode_to_device(unread).unwrap().body,
            ToDevice::Conversation(ConversationInfo {
                read: None,
                home: false,
                ..
            })
        ));
        assert!(decode_to_device(br#"{"v":1,"id":"m","type":"teleport"}"#).is_err());
    }

    #[test]
    fn archive_requests_are_explicit_and_conversation_metadata_defaults_to_active() {
        for archived in [true, false] {
            let body = FromDevice::ConversationArchive {
                conversation: ConversationId::new("c-1").unwrap(),
                archived,
            };
            let line = encode_line(&Envelope::new(MessageId::new("a-1").unwrap(), body.clone()));
            assert_eq!(decode_from_device(&line).unwrap().body, body);
        }
        for suffix in ["", ",\"archived\":null", ",\"archived\":\"true\""] {
            let line = format!(
                r#"{{"v":1,"id":"a-1","type":"conversation.archive","conversation":"c-1"{suffix}}}"#
            );
            assert!(matches!(
                decode_from_device(line.as_bytes()),
                Err(DecodeError::Bad { .. })
            ));
        }
        let old =
            br#"{"v":1,"id":"m","type":"conversation","conversation":"c-1","agent":"lab/main"}"#;
        let ToDevice::Conversation(mut info) = decode_to_device(old).unwrap().body else {
            panic!("not conversation metadata");
        };
        assert!(!info.archived);
        assert_eq!(info.revision, 0);
        for archived in [true, false] {
            info.archived = archived;
            let body = ToDevice::Conversation(info.clone());
            let line = encode_line(&Envelope::new(MessageId::new("m").unwrap(), body.clone()));
            assert_eq!(decode_to_device(&line).unwrap().body, body);
            assert_eq!(
                String::from_utf8_lossy(&line).contains("archived"),
                archived
            );
            assert!(!String::from_utf8_lossy(&line).contains("revision"));
        }
        info.revision = 7;
        let body = ToDevice::Conversation(info);
        let line = encode_line(&Envelope::new(MessageId::new("m").unwrap(), body.clone()));
        assert!(String::from_utf8_lossy(&line).contains(r#""revision":7"#));
        assert_eq!(decode_to_device(&line).unwrap().body, body);
        assert!(matches!(
            decode_to_device(br#"{"v":1,"id":"m","type":"conversation","conversation":"c-1","agent":"lab/main","revision":-1}"#),
            Err(DecodeError::Bad { .. })
        ));
    }

    #[test]
    fn a_full_attachment_chunk_fits_in_a_noise_message() {
        use base64::Engine as _;
        let data =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0xA5; ATTACHMENT_CHUNK]);
        let body = ToDevice::AttachmentData {
            attachment: "0b8f5f0e-4a1d-4f0f-8a43-6c2a7e9d1b21".into(),
            offset: 1_000_000_000,
            size: 2_000_000_000,
            data,
        };
        let line = encode_line(&Envelope::new(
            MessageId::new("0b8f5f0e-4a1d-4f0f-8a43-6c2a7e9d1b22").unwrap(),
            body,
        ));
        // A Noise transport message is 65,535 bytes, its tag 16 of them.
        assert!(line.len() <= 65_535 - 16, "{} bytes", line.len());
    }
    #[test]
    fn provisioning_responses_round_trip_and_older_auth_still_reads() {
        let id = MessageId::new("request").unwrap();
        for body in [
            ToDevice::Authenticated {
                person: "owner@example.org".into(),
                capabilities: vec!["sandboxes".into()],
            },
            ToDevice::SandboxesList {
                sandboxes: vec![SandboxInfo {
                    sandbox: "lab".into(),
                    runtime: None,
                    state: "created".into(),
                }],
            },
            ToDevice::RuntimesList {
                runtimes: vec![RuntimeInfo {
                    runtime: "hermes".into(),
                    name: "Hermes".into(),
                    description: "An agent runtime".into(),
                }],
            },
            ToDevice::OperationProgress {
                of: id.clone(),
                operation: "runtime.install".into(),
                sandbox: "lab".into(),
                message: "Installing".into(),
            },
            ToDevice::SandboxCreated {
                of: id.clone(),
                sandbox: "lab".into(),
            },
            ToDevice::RuntimeInstalled {
                of: id.clone(),
                sandbox: "lab".into(),
                runtime: "hermes".into(),
                login: "enclos connect lab -- hermes setup".into(),
            },
        ] {
            let line = encode_line(&Envelope::new(id.clone(), body.clone()));
            assert_eq!(decode_to_device(&line).unwrap().body, body);
        }
        assert_eq!(
            decode_to_device(
                br#"{"v":1,"id":"m","type":"authenticated","person":"owner@example.org"}"#
            )
            .unwrap()
            .body,
            ToDevice::Authenticated {
                person: "owner@example.org".into(),
                capabilities: vec![]
            }
        );
        assert!(
            decode_from_device(br#"{"v":1,"id":"m","type":"sandbox.create","sandbox":"lab"}"#)
                .is_err(),
            "creation must explicitly select a policy template"
        );
    }

    #[test]
    fn deletion_messages_are_typed_and_require_a_conversation_id() {
        let request = br#"{"v":1,"id":"d1","type":"conversation.delete","conversation":"c-1"}"#;
        assert!(
            matches!(decode_from_device(request).unwrap().body, FromDevice::ConversationDelete { conversation } if conversation.as_str()=="c-1")
        );
        assert!(decode_from_device(br#"{"v":1,"id":"d1","type":"conversation.delete"}"#).is_err());
        let response = br#"{"v":1,"id":"d2","type":"conversation.deleted","conversation":"c-1"}"#;
        assert!(
            matches!(decode_to_device(response).unwrap().body, ToDevice::ConversationDeleted { conversation } if conversation.as_str()=="c-1")
        );
    }
}

#[cfg(test)]
mod audit_compatibility_tests {
    use super::*;
    #[test]
    fn authenticated_capabilities_preserve_all_features_together() {
        let body = ToDevice::Authenticated {
            person: "alice".into(),
            capabilities: vec!["approval.close".into(), "sandboxes".into(), "audit".into()],
        };
        let wire = encode_line(&Envelope::new(
            MessageId::new("auth").unwrap(),
            body.clone(),
        ));
        assert_eq!(decode_to_device(&wire).unwrap().body, body);
    }

    #[test]
    fn older_authenticated_messages_have_no_audit_capability() {
        let auth = decode_to_device(br#"{"v":1,"id":"m","type":"authenticated","person":"alice"}"#)
            .unwrap();
        assert!(
            matches!(auth.body, ToDevice::Authenticated { capabilities, .. } if capabilities.is_empty())
        );
    }
}
