//! Sandbox policy requests: data from an agent or a proxy refusal, never authority.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Network,
    Write,
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    pub kind: AccessKind,
    /// One destination (host:port), or one absolute filesystem path.
    pub target: String,
    #[serde(default)]
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub request: String,
    pub sandbox: String,
    /// Empty for a proxy refusal, which cannot identify an agent.
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    pub access: Access,
    /// A short description; never a command for the host to execute.
    pub action: String,
    pub time: i64,
    pub state: String,
    /// The exact policy scope, generated on the host.
    pub change: String,
    pub restart: bool,
    pub revision: String,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
