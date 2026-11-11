//! Runtime questions with native choices, independent of any runtime's tool names.

use serde::{Deserialize, Serialize};

use crate::visible::{has_hidden, revealed};
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
    /// A native runtime gate, distinct from an ordinary information question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<RuntimeApprovalDefinition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApprovalAction {
    Once,
    Session,
    Always,
    Deny,
}

impl RuntimeApprovalAction {
    pub fn description(self) -> &'static str {
        match self {
            Self::Once => "Allow once",
            Self::Session => "Allow for session",
            Self::Always => "Always allow",
            Self::Deny => "Deny",
        }
    }

    pub fn typed_command(self) -> &'static str {
        match self {
            Self::Once => "/approve",
            Self::Session => "/approve session",
            Self::Always => "/approve always",
            Self::Deny => "/deny",
        }
    }
}

/// At most this many runtime patterns name what a session or always grant covers.
pub const MAX_APPROVAL_PATTERNS: usize = 16;

/// Only the native runtime supplies the already-redacted display command and allowed scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeApprovalDefinition {
    pub command: String,
    pub reason: String,
    pub actions: Vec<RuntimeApprovalAction>,
    #[serde(default)]
    pub smart_denied: bool,
    /// The runtime's own names of the patterns a session or always grant
    /// covers: every command matching one, not only this one. Required when
    /// either is offered, so the person sees how far the grant reaches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}

impl RuntimeApprovalDefinition {
    pub fn validate(&self) -> Result<(), String> {
        use RuntimeApprovalAction::{Always, Deny, Once, Session};
        text(&self.command, "Display command")?;
        text(&self.reason, "Approval reason")?;
        // The command is shown with its hidden characters written out; that
        // longer form must still fit, or the runtime keeps its text fallback.
        if revealed(&self.command).len() > MAX_QUESTION_BYTES {
            return Err("The display command is too long to show in full.".into());
        }
        if !self.actions.contains(&Deny)
            || (self.actions != [Deny] && !self.actions.contains(&Once))
            || self.actions.windows(2).any(|pair| pair[0] >= pair[1])
            || (self.actions.contains(&Always) && !self.actions.contains(&Session))
            || (self.smart_denied && self.actions.iter().any(|a| !matches!(a, Once | Deny)))
        {
            return Err("Runtime approval actions must be ordered, distinct and permitted by the native gate.".into());
        }
        if self.patterns.len() > MAX_APPROVAL_PATTERNS
            || self
                .patterns
                .iter()
                .enumerate()
                .any(|(i, p)| self.patterns[..i].contains(p))
        {
            return Err(format!(
                "A runtime approval names at most {MAX_APPROVAL_PATTERNS} distinct patterns."
            ));
        }
        for pattern in &self.patterns {
            text(pattern, "Approval pattern")?;
            if has_hidden(pattern, false) {
                return Err("An approval pattern holds a hidden character.".into());
            }
        }
        if self.grants_patterns() && self.patterns.is_empty() {
            return Err(
                "A session or always grant must name the runtime patterns it covers.".into(),
            );
        }
        Ok(())
    }

    /// Whether an offered action grants more than this one command.
    pub fn grants_patterns(&self) -> bool {
        self.actions.iter().any(|a| {
            matches!(
                a,
                RuntimeApprovalAction::Session | RuntimeApprovalAction::Always
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuestionAnswer {
    Choices { indices: Vec<u32> },
    Text { text: String },
    Skip,
    Approval { action: RuntimeApprovalAction },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionState {
    Pending,
    Answered,
    Skipped,
    Expired,
    Cancelled,
    /// A native decision made elsewhere without a disclosed action.
    Resolved,
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
        if let Some(approval) = &self.approval {
            approval.validate()?;
            if !self.choices.is_empty() || self.multiple {
                return Err("A runtime approval has typed actions, not question choices.".into());
            }
        }
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
    /// A runtime approval lists its typed commands only when `typed`: where the
    /// host's person owns the conversation, the only person whose typed
    /// decision the bridge passes on to the runtime.
    pub fn fallback_text(&self, typed: bool) -> String {
        if let Some(approval) = &self.approval {
            // What runs, with its hidden characters written out.
            let shown = revealed(&approval.command);
            // A command may contain markdown fences. Pick the shorter safe fence;
            // its two copies add at most roughly one command's length to the frame.
            let (marker, length) = ['`', '~']
                .into_iter()
                .map(|marker| {
                    let run = shown
                        .split(|c| c != marker)
                        .map(str::len)
                        .max()
                        .unwrap_or(0);
                    (marker, (run + 1).max(3))
                })
                .min_by_key(|(_, length)| *length)
                .expect("two fence markers");
            let fence = marker.to_string().repeat(length);
            let command = format!("{fence}sh\n{shown}\n{fence}");
            let warning = if approval.command.is_ascii() {
                ""
            } else {
                "The command holds characters outside ASCII, some of which look like others. Check each one.\n\n"
            };
            let actions = if typed {
                approval
                    .actions
                    .iter()
                    .map(|action| format!("{}: `{}`", action.description(), action.typed_command()))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                let offered = approval
                    .actions
                    .iter()
                    .map(|action| action.description())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "Offered: {offered}. Only the host's person can answer this approval, from an updated app."
                )
            };
            let scopes = if approval.grants_patterns() {
                format!(
                    "A session or always grant covers every command matching: {}. An always grant persists in the runtime until removed there. ",
                    approval.patterns.join("; ")
                )
            } else {
                String::new()
            };
            return format!(
                "{}\n\n{command}\n\n{warning}Why: {}\n\n{actions}\n\n{scopes}The sandbox policy still applies.",
                self.text,
                revealed(&approval.reason)
            );
        }
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
        match (&definition.approval, self) {
            (Some(approval), Self::Approval { action }) if approval.actions.contains(action) => {
                return bounded(self, MAX_ANSWER_BYTES, "Answer");
            }
            (Some(_), _) | (None, Self::Approval { .. }) => {
                return Err("A runtime approval requires one of its offered typed actions.".into());
            }
            (None, _) => {}
        }
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
            Self::Approval { .. } => unreachable!("approval answers were checked above"),
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
        if (self.definition.approval.is_some() && self.state == QuestionState::Skipped)
            || (self.definition.approval.is_none() && self.state == QuestionState::Resolved)
        {
            return Err("This terminal state does not belong to this kind of control.".into());
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
            approval: None,
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
        let fallback = original.fallback_text(true);
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

    fn approval_definition() -> QuestionDefinition {
        QuestionDefinition {
            id: QuestionId::new("approval-1").unwrap(),
            text: "Command approval".into(),
            choices: vec![],
            multiple: false,
            approval: Some(RuntimeApprovalDefinition {
                command: "printf 'bonjour 🤖'\nprintf 'done'".into(),
                reason: "The runtime asks for permission.".into(),
                actions: vec![
                    RuntimeApprovalAction::Once,
                    RuntimeApprovalAction::Session,
                    RuntimeApprovalAction::Always,
                    RuntimeApprovalAction::Deny,
                ],
                smart_denied: false,
                patterns: vec!["recursive delete".into()],
            }),
        }
    }

    #[test]
    fn approval_actions_are_explicit_and_cannot_be_answered_as_a_question() {
        use RuntimeApprovalAction::{Deny, Once};
        let mut approval = approval_definition();
        approval.validate().unwrap();
        for action in &approval.approval.as_ref().unwrap().actions {
            QuestionAnswer::Approval { action: *action }
                .validate(&approval)
                .unwrap();
        }
        for answer in [
            QuestionAnswer::Skip,
            QuestionAnswer::Text {
                text: "/approve".into(),
            },
            QuestionAnswer::Choices { indices: vec![0] },
        ] {
            assert!(answer.validate(&approval).is_err());
        }
        assert!(
            QuestionAnswer::Approval { action: Once }
                .validate(&definition(false))
                .is_err()
        );
        approval.approval.as_mut().unwrap().actions = vec![Deny];
        approval.validate().unwrap();
        assert!(
            QuestionAnswer::Approval { action: Once }
                .validate(&approval)
                .is_err()
        );
        QuestionAnswer::Approval { action: Deny }
            .validate(&approval)
            .unwrap();
    }

    #[test]
    fn runtime_scopes_preserve_deny_only_and_smart_denial_restrictions() {
        use RuntimeApprovalAction::{Always, Deny, Once, Session};
        let original = approval_definition().approval.unwrap();
        for actions in [
            vec![],
            vec![Once],
            vec![Once, Deny, Deny],
            vec![Deny, Once],
            vec![Session, Deny],
            vec![Once, Always, Deny],
        ] {
            assert!(
                RuntimeApprovalDefinition {
                    actions,
                    ..original.clone()
                }
                .validate()
                .is_err()
            );
        }
        for actions in [vec![Deny], vec![Once, Deny]] {
            RuntimeApprovalDefinition {
                actions,
                smart_denied: true,
                ..original.clone()
            }
            .validate()
            .unwrap();
        }
        assert!(
            RuntimeApprovalDefinition {
                smart_denied: true,
                ..original
            }
            .validate()
            .is_err()
        );
        let mut invalid = approval_definition();
        invalid.choices = vec!["Approve".into()];
        assert!(invalid.validate().is_err());
        invalid.choices.clear();
        invalid.multiple = true;
        assert!(invalid.validate().is_err());
        invalid.multiple = false;
        invalid.approval.as_mut().unwrap().command = "hello\0world".into();
        assert!(invalid.validate().is_err());
        invalid.approval.as_mut().unwrap().command = "hello\r\nworld\tend".into();
        invalid.validate().unwrap();
    }

    #[test]
    fn externally_resolved_approvals_never_invent_a_decision_or_look_like_skip() {
        let mut approval = QuestionInfo {
            definition: approval_definition(),
            ..info()
        };
        approval.state = QuestionState::Resolved;
        assert!(approval.state.is_terminal());
        approval.validate().unwrap();
        approval.answer = Some(QuestionAnswer::Approval {
            action: RuntimeApprovalAction::Once,
        });
        assert!(approval.validate().is_err());
        approval.state = QuestionState::Answered;
        approval.validate().unwrap();
        approval.answer = None;
        approval.state = QuestionState::Skipped;
        assert!(approval.validate().is_err());
        assert!(
            QuestionInfo {
                state: QuestionState::Resolved,
                ..info()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn approval_metadata_and_typed_decisions_roundtrip_on_both_legs() {
        let id = MessageId::new("approval-wire").unwrap();
        let definition = approval_definition();
        let answer = QuestionAnswer::Approval {
            action: RuntimeApprovalAction::Deny,
        };
        let from_device = FromDevice::QuestionAnswer {
            question: definition.id.clone(),
            revision: 0,
            answer: answer.clone(),
        };
        assert_eq!(
            decode_from_device(&encode_line(&Envelope::new(
                id.clone(),
                from_device.clone()
            )))
            .unwrap()
            .body,
            from_device
        );
        let from_bridge = FromBridge::QuestionAnswer {
            question: definition.id.clone(),
            conversation: info().conversation,
            answer: answer.clone(),
        };
        assert_eq!(
            decode_from_bridge(&encode_line(&Envelope::new(
                id.clone(),
                from_bridge.clone()
            )))
            .unwrap()
            .body,
            from_bridge
        );
        let ask = FromPlugin::QuestionAsk {
            question: definition.clone(),
            conversation: info().conversation,
        };
        assert_eq!(
            decode_from_plugin(&encode_line(&Envelope::new(id.clone(), ask.clone())))
                .unwrap()
                .body,
            ask
        );
        let result = ToDevice::QuestionResult {
            of: id.clone(),
            question: QuestionInfo {
                definition,
                state: QuestionState::Answered,
                revision: 1,
                answer: Some(answer),
                ..info()
            },
        };
        assert_eq!(
            decode_to_device(&encode_line(&Envelope::new(id, result.clone())))
                .unwrap()
                .body,
            result
        );
        assert_eq!(
            serde_json::to_string(&Capability::RuntimeApprovals).unwrap(),
            "\"runtime_approvals\""
        );
    }

    #[test]
    fn ordinary_questions_remain_compatible_without_approval_metadata() {
        let old = r#"{"id":"old","text":"Which?","choices":["One","Two"],"multiple":false}"#;
        let old: QuestionDefinition = serde_json::from_str(old).unwrap();
        old.validate().unwrap();
        assert!(old.approval.is_none());
        assert!(!serde_json::to_string(&old).unwrap().contains("approval"));
        assert!(serde_json::from_str::<RuntimeApprovalAction>("\"approve_all\"").is_err());
    }

    #[test]
    fn full_command_fallback_is_literal_and_bounded_even_with_fences_or_many_lines() {
        for command in [
            format!("echo ok\n{}\n{}", "`".repeat(11000), "~".repeat(11000)),
            format!("echo ok{}", "\n".repeat(MAX_QUESTION_BYTES / 2 - 512)),
        ] {
            let mut question = approval_definition();
            question.approval.as_mut().unwrap().command = command.clone();
            question.validate().unwrap();
            let fallback = question.fallback_text(true);
            assert!(fallback.contains(&command));
            assert!(fallback.contains("/approve always"));
            assert!(!fallback.contains("skip"));
            let body = ToDevice::Message(ConversationMessage {
                conversation: info().conversation,
                agent: "lab/main".into(),
                from: "agent".into(),
                text: fallback,
                kind: "runtime_approval".into(),
                time: 1,
                seq: 1,
                question: Some(question.id.clone()),
                attachments: vec![],
            });
            assert!(
                encode_line(&Envelope::new(
                    MessageId::new("m".repeat(128)).unwrap(),
                    body
                ))
                .len()
                    < 60 * 1024
            );
            let metadata = ToDevice::QuestionResult {
                of: MessageId::new("receipt").unwrap(),
                question: QuestionInfo {
                    definition: question,
                    ..info()
                },
            };
            assert!(
                encode_line(&Envelope::new(
                    MessageId::new("metadata").unwrap(),
                    metadata
                ))
                .len()
                    < 60 * 1024
            );
        }
        let mut too_large = approval_definition();
        too_large.approval.as_mut().unwrap().command = "x".repeat(MAX_QUESTION_BYTES);
        assert!(too_large.validate().is_err());
    }

    #[test]
    fn session_and_always_grants_name_the_patterns_they_cover() {
        use RuntimeApprovalAction::{Deny, Once, Session};
        let original = approval_definition().approval.unwrap();
        for patterns in [
            vec![],
            vec!["".into()],
            vec!["recursive\u{202E} delete".into()],
            vec!["a".into(), "a".into()],
            (0..=MAX_APPROVAL_PATTERNS)
                .map(|i| format!("p{i}"))
                .collect(),
        ] {
            assert!(
                RuntimeApprovalDefinition {
                    patterns,
                    ..original.clone()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            RuntimeApprovalDefinition {
                actions: vec![Once, Session, Deny],
                patterns: vec![],
                ..original.clone()
            }
            .validate()
            .is_err()
        );
        // Once and Deny grant nothing beyond this command.
        RuntimeApprovalDefinition {
            actions: vec![Once, Deny],
            patterns: vec![],
            ..original
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn approval_fallback_reveals_hidden_characters_and_flags_non_ascii() {
        let mut question = approval_definition();
        let approval = question.approval.as_mut().unwrap();
        approval.command = "ls\u{202E} -la\r\ncurl https://ex\u{0430}mple.com".into();
        approval.reason = "Pipe\u{200B} to shell".into();
        let fallback = question.fallback_text(true);
        assert!(fallback.contains("ls⟨U+202E⟩ -la⟨U+000D⟩\ncurl https://ex\u{0430}mple.com"));
        assert!(fallback.contains("Why: Pipe⟨U+200B⟩ to shell"));
        assert!(!fallback.contains('\u{202E}') && !fallback.contains('\u{200B}'));
        assert!(fallback.contains("outside ASCII"));
        assert!(fallback.contains("every command matching: recursive delete"));
        assert!(fallback.contains("until removed there"));
        let mut ascii = approval_definition();
        ascii.approval.as_mut().unwrap().command = "rm -rf ./build\tdist".into();
        let ascii = ascii.fallback_text(true);
        assert!(!ascii.contains("outside ASCII"));
        assert!(ascii.contains("rm -rf ./build⟨tab⟩dist"));
        // A non-ASCII letter that is not hidden is shown as it is, and flagged.
        assert!(
            approval_definition()
                .fallback_text(true)
                .contains("outside ASCII")
        );
        let mut long = approval_definition();
        // Each three-byte hidden character takes twelve once written out.
        long.approval.as_mut().unwrap().command = "\u{200B}".repeat(MAX_QUESTION_BYTES / 9);
        assert!(long.validate().is_err());
    }

    #[test]
    fn approval_fallback_lists_typed_commands_only_where_they_are_passed_on() {
        let question = approval_definition();
        let typed = question.fallback_text(true);
        assert!(typed.contains("/approve always") && typed.contains("/deny"));
        let guest = question.fallback_text(false);
        assert!(!guest.contains("/approve") && !guest.contains("/deny"));
        assert!(guest.contains("Offered: Allow once, Allow for session, Always allow, Deny."));
        assert!(guest.contains("Only the host's person"));
        assert!(guest.contains("printf 'done'"));
        // An ordinary question reads the same either way.
        assert_eq!(
            definition(false).fallback_text(false),
            definition(false).fallback_text(true)
        );
    }
}
