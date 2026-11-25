//! A person's current requests, projected from the bridge's canonical records.
use crate::ConversationId;
use crate::held_task::WaitsOn;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenItemKind {
    Question,
    RuntimeApproval,
    HeldTask,
    PolicyRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenItem {
    /// Opaque source generation, used only to dismiss this exact reminder.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The existing question, held-task or policy-request id. Kind and agent scope it.
    pub id: String,
    pub kind: OpenItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<ConversationId>,
    pub summary: String,
    pub since: i64,
    pub expired: bool,
    /// Who a held task waits for: the team's own schedule, or the person. Only on
    /// `held_task` items; absent elsewhere and in older bridges, it reads as `person`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waits_on: Option<WaitsOn>,
}

impl OpenItemKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::RuntimeApproval => "runtime_approval",
            Self::HeldTask => "held_task",
            Self::PolicyRequest => "policy_request",
        }
    }
}
