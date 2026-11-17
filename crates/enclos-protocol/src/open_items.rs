//! A person's current requests, projected from the bridge's canonical records.
use crate::ConversationId;
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
}
