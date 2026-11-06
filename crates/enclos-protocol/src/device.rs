//! The device leg's messages (`docs/protocol.md`, Messages after the
//! handshake), each inside a Noise transport message. Bytes travel as
//! base64url text ([`crate::pairing::encode`]).

use serde::{Deserialize, Serialize};

use crate::envelope::{DecodeError, Envelope, decode};
use crate::ids::{ConversationId, MessageId};
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
    /// The person read the conversation up to message `seq`, on this
    /// device: the bridge keeps it, for their other devices and the next.
    #[serde(rename = "conversation.read")]
    ConversationRead {
        conversation: ConversationId,
        seq: i64,
    },
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
    "auth",
    "pair.request",
    "agents",
    "conversation.new",
    "message.send",
    "conversation.rename",
    "conversation.read",
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
    /// messages, and again whenever its name or how far it was read changes.
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
    "authenticated",
    "pair.accepted",
    "pair.refused",
    "agents.list",
    "conversation",
    "message",
    "typing",
    "tool",
    "attachment.data",
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
    /// The agent's Home: where what has no conversation of its own goes
    /// (cron jobs, the runtime's notices). Shown first, never empty.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub home: bool,
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

pub fn decode_from_device(bytes: &[u8]) -> Result<Envelope<FromDevice>, DecodeError> {
    decode(bytes, FROM_DEVICE_TYPES)
}

pub fn decode_to_device(bytes: &[u8]) -> Result<Envelope<ToDevice>, DecodeError> {
    decode(bytes, TO_DEVICE_TYPES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_line;

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
            FromDevice::ConversationRead {
                conversation: ConversationId::new("c-1").unwrap(),
                seq: 7,
            },
            FromDevice::DeviceForget,
            FromDevice::AttachmentGet {
                attachment: "a-1".into(),
                offset: 45_000,
            },
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
            home: false,
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
            home: true,
        });
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
}
