//! The device leg's messages (`docs/protocol.md`, Messages after the
//! handshake), each inside a Noise transport message. Bytes travel as
//! base64url text ([`crate::pairing::encode`]).

use serde::{Deserialize, Serialize};

use crate::envelope::{DecodeError, Envelope, decode, encode_line};
use crate::ids::{ConversationId, MAX_ID_BYTES, MessageId};
use crate::noise::MAX_NOISE_MESSAGE;
use crate::plugin::{Capability, ErrorBody, ToolStep};

/// What a device sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FromDevice {
    /// First after the handshake of a paired device: its id on this host
    /// and its hardware key's DER signature of the handshake hash.
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        push: Option<PushToken>,
    },
    #[serde(rename = "agents")]
    Agents,
    #[serde(rename = "conversation.new")]
    ConversationNew {
        conversation: ConversationId,
        agent: String,
    },
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
    #[serde(rename = "sync")]
    Sync { since: i64 },
    #[serde(rename = "push.token")]
    PushTokenUpdate(PushToken),
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

pub const FROM_DEVICE_TYPES: &[&str] = &[
    "auth",
    "pair.request",
    "agents",
    "conversation.new",
    "message.send",
    "conversation.rename",
    "sync",
    "push.token",
    "ack",
    "error",
];

/// What the bridge sends a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToDevice {
    /// The device is known and its signature holds: who it speaks for.
    #[serde(rename = "authenticated")]
    Authenticated { person: String },
    #[serde(rename = "pair.accepted")]
    PairAccepted { device: String, push_key: String },
    #[serde(rename = "pair.refused")]
    PairRefused { reason: String },
    #[serde(rename = "agents.list")]
    AgentsList { agents: Vec<AgentInfo> },
    /// One of the person's conversations: each at `sync`, before the
    /// messages, and again whenever its name changes.
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
    #[serde(rename = "synced")]
    Synced { seq: i64 },
    #[serde(rename = "ack")]
    Ack { of: MessageId },
    #[serde(rename = "error")]
    Error(ErrorBody),
}

pub const TO_DEVICE_TYPES: &[&str] = &[
    "authenticated",
    "pair.accepted",
    "pair.refused",
    "agents.list",
    "conversation",
    "message",
    "typing",
    "tool",
    "synced",
    "ack",
    "error",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken {
    pub kind: String,
    pub token: String,
}

/// An agent a person may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    /// `<sandbox>/<agent>`.
    pub agent: String,
    pub runtime: String,
    pub capabilities: Vec<Capability>,
    pub abilities: Vec<String>,
}

/// A conversation: its agent, and its name when it has one.
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
            conversation: ConversationId::new("c-1").unwrap(),
            agent: "lab/main".into(),
            from: "agent".into(),
            text: text.into(),
            kind: "reply".into(),
            time: 1_700_000_000,
            seq: 1,
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

    #[test]
    fn device_messages_round_trip() {
        let id = || MessageId::new("m-1").unwrap();
        for body in [
            FromDevice::Auth {
                device: "d1".into(),
                sig: "c2ln".into(),
            },
            FromDevice::Agents,
            FromDevice::MessageSend {
                conversation: ConversationId::new("c-1").unwrap(),
                text: "hi".into(),
            },
            FromDevice::Sync { since: 4 },
        ] {
            let line = encode_line(&Envelope::new(id(), body.clone()));
            assert_eq!(decode_from_device(&line).unwrap().body, body);
        }
        let body = ToDevice::Message(ConversationMessage {
            conversation: ConversationId::new("c-1").unwrap(),
            agent: "lab/main".into(),
            from: "agent".into(),
            text: "hello".into(),
            kind: "reply".into(),
            time: 1_800_000_000,
            seq: 7,
        });
        let line = encode_line(&Envelope::new(id(), body.clone()));
        assert_eq!(decode_to_device(&line).unwrap().body, body);
        assert!(decode_to_device(br#"{"v":1,"id":"m","type":"teleport"}"#).is_err());
    }
}
