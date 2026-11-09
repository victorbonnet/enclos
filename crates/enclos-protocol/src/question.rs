//! Runtime questions with native choices, independent of any runtime's tool names.

use serde::{Deserialize, Serialize};

use crate::{ConversationId, QuestionId};

pub const MAX_CHOICES: usize = 12;
pub const MAX_QUESTION_BYTES: usize = 24 * 1024;
pub const MAX_ANSWER_BYTES: usize = 8 * 1024;
pub const MAX_QUESTION_INFO_BYTES: usize = 48 * 1024;
pub const MAX_SYNC_QUESTIONS: usize = 128;

/// The question's immutable content. Labels are displayed literally and retain their order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionDefinition {
    pub id: QuestionId,
    pub text: String,
    #[serde(default)]
    pub choices: Vec<String>,
    #[serde(default)]
    pub multiple: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuestionAnswer {
    Choices { indices: Vec<u32> },
    Text { text: String },
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionState {
    Pending,
    Answered,
    Skipped,
    Expired,
    Cancelled,
}

impl QuestionState {
    pub fn is_terminal(self) -> bool {
        self != Self::Pending
    }
}

/// Canonical bridge metadata. A later revision can settle a card, never reopen it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuestionInfo {
    #[serde(flatten)]
    pub definition: QuestionDefinition,
    pub conversation: ConversationId,
    /// The requesting agent, `sandbox/agent`, including in a group.
    pub agent: String,
    pub state: QuestionState,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<QuestionAnswer>,
}

fn text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be blank."));
    }
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(format!("{field} holds a control character."));
    }
    Ok(())
}

fn bounded(value: &impl Serialize, limit: usize, field: &str) -> Result<(), String> {
    let size = serde_json::to_vec(value).map_err(|e| e.to_string())?.len();
    if size > limit {
        return Err(format!("{field} is larger than {limit} encoded bytes."));
    }
    Ok(())
}

impl QuestionDefinition {
    pub fn validate(&self) -> Result<(), String> {
        text(&self.text, "Question")?;
        if self.choices.len() > MAX_CHOICES {
            return Err(format!(
                "A question supports at most {MAX_CHOICES} choices."
            ));
        }
        if self.multiple && self.choices.is_empty() {
            return Err("Multiple selection requires choices.".into());
        }
        for label in &self.choices {
            text(label, "Choice label")?;
        }
        bounded(self, MAX_QUESTION_BYTES, "Question")
    }

    /// Old apps display ordinary text and answer through the runtime's text interceptor.
    pub fn fallback_text(&self) -> String {
        let mut result = self.text.clone();
        for (index, label) in self.choices.iter().enumerate() {
            result.push_str(&format!("\n{}. {label}", index + 1));
        }
        result.push_str(if self.choices.is_empty() {
            "\nReply with your answer, or reply \"skip\" to skip this question."
        } else if self.multiple {
            "\nChoose one or more options. Reply with their numbers separated by commas, or your own answer. Reply \"skip\" to skip this question."
        } else {
            "\nReply with an option's number, its text, or your own answer. Reply \"skip\" to skip this question."
        });
        result
    }
}

impl QuestionAnswer {
    pub fn validate(&self, definition: &QuestionDefinition) -> Result<(), String> {
        definition.validate()?;
        match self {
            Self::Choices { indices } => {
                if indices.is_empty() || (!definition.multiple && indices.len() != 1) {
                    return Err("Select an answer in the question's selection mode.".into());
                }
                let mut seen = std::collections::HashSet::new();
                for index in indices {
                    if usize::try_from(*index).map_or(true, |i| i >= definition.choices.len())
                        || !seen.insert(index)
                    {
                        return Err(
                            "Choice indices must be distinct and belong to this question.".into(),
                        );
                    }
                }
            }
            Self::Text { text: value } => text(value, "Answer")?,
            Self::Skip => {}
        }
        bounded(self, MAX_ANSWER_BYTES, "Answer")
    }
}

impl QuestionInfo {
    pub fn validate(&self) -> Result<(), String> {
        self.definition.validate()?;
        if self.agent.is_empty()
            || self.agent.len() > 512
            || self.agent.chars().any(char::is_control)
        {
            return Err("A question must name its requesting agent.".into());
        }
        if self.revision > i64::MAX as u64 {
            return Err(
                "Question revision cannot be represented by the conversation cache.".into(),
            );
        }
        match (&self.state, &self.answer) {
            (QuestionState::Answered, Some(answer)) if !matches!(answer, QuestionAnswer::Skip) => {
                answer.validate(&self.definition)?;
            }
            (QuestionState::Answered, _) | (_, Some(_)) => {
                return Err("Question state and answer disagree.".into());
            }
            (_, None) => {}
        }
        bounded(self, MAX_QUESTION_INFO_BYTES, "Question metadata")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{
        ConversationMessage, FromDevice, ToDevice, decode_from_device, decode_to_device,
    };
    use crate::plugin::{
        Capability, FromBridge, FromPlugin, decode_from_bridge, decode_from_plugin,
    };
    use crate::{Envelope, MessageId, encode_line};

    fn definition(multiple: bool) -> QuestionDefinition {
        QuestionDefinition {
            id: QuestionId::new("q-1").unwrap(),
            text: "Que doit-on pouvoir choisir depuis le hub ?".into(),
            choices: vec![
                "Résultats (Recommended)".into(),
                "Classement Ballon d'Or".into(),
            ],
            multiple,
        }
    }

    fn info() -> QuestionInfo {
        QuestionInfo {
            definition: definition(false),
            conversation: ConversationId::new("home.lab.main").unwrap(),
            agent: "lab/main".into(),
            state: QuestionState::Pending,
            revision: 0,
            answer: None,
        }
    }

    #[test]
    fn immutable_labels_and_selection_modes_are_validated_without_sentinel_injection() {
        let one = definition(false);
        assert!(one.validate().is_ok());
        assert!(
            QuestionAnswer::Choices { indices: vec![1] }
                .validate(&one)
                .is_ok()
        );
        for indices in [vec![], vec![0, 1], vec![2], vec![u32::MAX], vec![0, 0]] {
            assert!(QuestionAnswer::Choices { indices }.validate(&one).is_err());
        }
        let many = definition(true);
        assert!(
            QuestionAnswer::Choices {
                indices: vec![1, 0]
            }
            .validate(&many)
            .is_ok()
        );
        assert!(
            QuestionAnswer::Choices {
                indices: vec![1, 1]
            }
            .validate(&many)
            .is_err()
        );
        for value in ["", " \t\n", "\0skipped", "\0cancelled", "answer\u{1b}[2J"] {
            assert!(
                QuestionAnswer::Text { text: value.into() }
                    .validate(&many)
                    .is_err()
            );
        }
        assert!(
            QuestionAnswer::Text {
                text: "Une autre option\navec un détail".into()
            }
            .validate(&many)
            .is_ok()
        );
        assert!(QuestionAnswer::Skip.validate(&many).is_ok());
        let open = QuestionDefinition {
            choices: vec![],
            multiple: false,
            ..one
        };
        assert!(open.validate().is_ok());
        assert!(
            QuestionAnswer::Text { text: "Oui".into() }
                .validate(&open)
                .is_ok()
        );
        assert!(
            QuestionAnswer::Choices { indices: vec![0] }
                .validate(&open)
                .is_err()
        );
        assert!(
            QuestionDefinition {
                multiple: true,
                ..open
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn bounds_use_encoded_bytes_and_never_truncate_choices() {
        let original = definition(false);
        for invalid in [
            QuestionDefinition {
                choices: vec!["one".into(); MAX_CHOICES + 1],
                ..original.clone()
            },
            QuestionDefinition {
                choices: vec![" ".into()],
                ..original.clone()
            },
            QuestionDefinition {
                choices: vec!["\0skipped".into()],
                ..original.clone()
            },
            QuestionDefinition {
                text: "🤖".repeat(MAX_QUESTION_BYTES / 4),
                ..original.clone()
            },
            QuestionDefinition {
                text: "\n".repeat(MAX_QUESTION_BYTES / 2) + "x",
                ..original.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
        assert_eq!(original.choices.len(), 2);
        assert!(
            QuestionAnswer::Text {
                text: "x".repeat(MAX_ANSWER_BYTES)
            }
            .validate(&original)
            .is_err()
        );
        let fallback = original.fallback_text();
        for label in &original.choices {
            assert!(fallback.contains(label));
        }
        assert!(fallback.contains("skip"));
    }

    #[test]
    fn terminal_metadata_has_only_its_valid_answer_and_never_an_overflowed_revision() {
        let pending = info();
        assert!(pending.validate().is_ok());
        let answer = Some(QuestionAnswer::Choices { indices: vec![0] });
        assert!(
            QuestionInfo {
                answer: answer.clone(),
                ..pending.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            QuestionInfo {
                state: QuestionState::Answered,
                ..pending.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            QuestionInfo {
                state: QuestionState::Answered,
                answer,
                ..pending.clone()
            }
            .validate()
            .is_ok()
        );
        for state in [
            QuestionState::Skipped,
            QuestionState::Expired,
            QuestionState::Cancelled,
        ] {
            assert!(state.is_terminal());
            assert!(
                QuestionInfo {
                    state,
                    ..pending.clone()
                }
                .validate()
                .is_ok()
            );
            assert!(
                QuestionInfo {
                    state,
                    answer: Some(QuestionAnswer::Skip),
                    ..pending.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            QuestionInfo {
                revision: u64::MAX,
                ..pending
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn questions_round_trip_on_both_legs_and_old_hellos_and_messages_remain_readable() {
        let question = info();
        let answer = QuestionAnswer::Choices { indices: vec![0] };
        let id = MessageId::new("request-1").unwrap();
        for body in [
            FromPlugin::QuestionAsk {
                conversation: question.conversation.clone(),
                question: question.definition.clone(),
            },
            FromPlugin::QuestionUpdate {
                question: question.definition.id.clone(),
                state: QuestionState::Answered,
                answer: Some(answer.clone()),
                of: Some(id.clone()),
            },
        ] {
            let encoded = encode_line(&Envelope::new(id.clone(), body.clone()));
            assert_eq!(decode_from_plugin(&encoded).unwrap().body, body);
        }
        for body in [
            FromBridge::QuestionAnswer {
                conversation: question.conversation.clone(),
                question: question.definition.id.clone(),
                answer: answer.clone(),
            },
            FromBridge::QuestionSync {
                questions: vec![question.definition.id.clone()],
            },
        ] {
            let encoded = encode_line(&Envelope::new(id.clone(), body.clone()));
            assert_eq!(decode_from_bridge(&encoded).unwrap().body, body);
        }
        let request = FromDevice::QuestionAnswer {
            question: question.definition.id.clone(),
            revision: 0,
            answer,
        };
        assert_eq!(
            decode_from_device(&encode_line(&Envelope::new(id.clone(), request.clone())))
                .unwrap()
                .body,
            request
        );
        for body in [
            ToDevice::Question {
                question: question.clone(),
            },
            ToDevice::QuestionResult {
                of: id.clone(),
                question,
            },
        ] {
            assert_eq!(
                decode_to_device(&encode_line(&Envelope::new(id.clone(), body.clone())))
                    .unwrap()
                    .body,
                body
            );
        }
        let old = br#"{"v":1,"id":"h","type":"hello","token":"token"}"#;
        let FromBridge::Hello { capabilities, .. } = decode_from_bridge(old).unwrap().body else {
            panic!("hello")
        };
        assert!(capabilities.is_empty());
        assert_eq!(
            serde_json::to_string(&Capability::Questions).unwrap(),
            "\"questions\""
        );
        let old = br#"{"v":1,"id":"m","type":"message","conversation":"c","agent":"lab/main","from":"agent","text":"old","kind":"reply","time":1,"seq":1}"#;
        let ToDevice::Message(message) = decode_to_device(old).unwrap().body else {
            panic!("message")
        };
        assert!(message.question.is_none());
        assert!(
            !serde_json::to_string(&message)
                .unwrap()
                .contains("question")
        );
        let with_question = ConversationMessage {
            question: Some(QuestionId::new("q-1").unwrap()),
            ..message
        };
        assert_eq!(
            serde_json::from_str::<ConversationMessage>(
                &serde_json::to_string(&with_question).unwrap()
            )
            .unwrap(),
            with_question
        );
    }

    #[test]
    fn large_question_and_answer_metadata_stays_below_a_noise_frame_budget() {
        let mut question = info();
        question.definition.id = QuestionId::new("q".repeat(128)).unwrap();
        question.definition.text = "🤖".repeat(4000);
        question.definition.choices = vec!["x".repeat(7000)];
        question.conversation = ConversationId::new("c".repeat(128)).unwrap();
        question.agent = format!("lab/{}", "a".repeat(508));
        question.state = QuestionState::Answered;
        question.answer = Some(QuestionAnswer::Text {
            text: "返".repeat(2500),
        });
        question.validate().unwrap();
        let id = MessageId::new("m".repeat(128)).unwrap();
        let body = ToDevice::QuestionResult {
            of: id.clone(),
            question,
        };
        assert!(encode_line(&Envelope::new(id, body)).len() < 60 * 1024);
    }
}
