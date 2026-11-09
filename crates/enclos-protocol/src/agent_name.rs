//! Shared agent display names. The agent's stable address is never renamed.
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_NAME_CHARS: usize = 100;
pub const MAX_NAME_BYTES: usize = 400;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameMetadata {
    pub revision: i64,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentName {
    pub agent: String,
    pub revision: i64,
    pub display_name: Option<String>,
    pub of: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameSet {
    pub agent: String,
    pub revision: i64,
    /// Required, but explicitly null restores the agent's stable identifier.
    #[serde(deserialize_with = "required_name")]
    pub display_name: Option<String>,
}

fn required_name<'de, D: Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(value)
}

/// Names may contain accented characters and emoji, but never invisible line/control syntax.
pub fn normalize(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    // Check before trimming so a newline is not silently accepted at an edge.
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err("An agent name cannot contain control characters or line breaks.".into());
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("Enter an agent name, or restore its original name.".into());
    }
    if value.len() > MAX_NAME_BYTES || value.chars().count() > MAX_NAME_CHARS {
        return Err("An agent name may contain at most 100 characters and 400 UTF-8 bytes.".into());
    }
    Ok(Some(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Envelope, MessageId,
        device::{FromDevice, ToDevice, decode_from_device, decode_to_device},
    };

    #[test]
    fn unicode_names_and_explicit_clear_round_trip_with_stable_agent_address() {
        for display_name in [Some("Gégé Commit".into()), None] {
            let request = Envelope::new(
                MessageId::new("name-1").unwrap(),
                FromDevice::AgentNameSet(NameSet {
                    agent: "lab/comptoir-dev".into(),
                    revision: 7,
                    display_name: display_name.clone(),
                }),
            );
            let encoded = serde_json::to_vec(&request).unwrap();
            assert_eq!(decode_from_device(&encoded).unwrap(), request);
            let reply = Envelope::new(
                MessageId::new("reply-1").unwrap(),
                ToDevice::AgentName(AgentName {
                    agent: "lab/comptoir-dev".into(),
                    revision: 8,
                    display_name,
                    of: "name-1".into(),
                }),
            );
            assert_eq!(
                decode_to_device(&serde_json::to_vec(&reply).unwrap()).unwrap(),
                reply
            );
        }
        assert!(
            decode_from_device(
                br#"{"v":1,"id":"m1","type":"agent.name.set","agent":"lab/main","revision":0}"#
            )
            .is_err()
        );
        assert!(decode_from_device(br#"{"v":1,"id":"m1","type":"agent.name.set","agent":"lab/main","revision":0,"display_name":false}"#).is_err());
    }

    #[test]
    fn names_are_trimmed_bounded_unicode_and_never_multiline() {
        assert_eq!(
            normalize(Some("  Gégé Commit  ")).unwrap().as_deref(),
            Some("Gégé Commit")
        );
        assert_eq!(normalize(None).unwrap(), None);
        assert!(normalize(Some(&"🦀".repeat(100))).is_ok());
        for invalid in [
            "".into(),
            "  ".into(),
            "Gégé\nCommit".into(),
            "\tGégé".into(),
            "a\u{2028}b".into(),
            "a\u{2029}b".into(),
            "a\0b".into(),
            "x".repeat(101),
            "🦀".repeat(101),
        ] {
            assert!(normalize(Some(&invalid)).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn legacy_agent_lists_keep_the_identifier_and_new_hosts_advertise_name_support() {
        let legacy: crate::device::AgentInfo = serde_json::from_str(r#"{"agent":"lab/comptoir-dev","runtime":"hermes","capabilities":[],"abilities":["read"]}"#).unwrap();
        assert_eq!(legacy.display_name, None);
        assert_eq!(legacy.name_revision, 0);
        assert!(!legacy.can_edit_name);
        let sent = serde_json::to_value(legacy).unwrap();
        assert_eq!(sent["agent"], "lab/comptoir-dev");
        assert!(
            sent.get("can_edit_name").is_some(),
            "presence distinguishes a new host from an older one"
        );
    }
}
