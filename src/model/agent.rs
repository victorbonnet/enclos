//! Agents (design §3). An agent is a named identity of the sandbox's
//! runtime, with its own configuration, memory, skills, sessions and
//! channels. It shares the sandbox's runtime, policy, proxy and secrets. It
//! is not a process and not a permission boundary: the runtime adapter
//! decides how many processes run it, and the sandbox is the boundary.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::Timestamp;
use super::sandbox::is_short_name;

/// An agent name: the sandbox naming rule (`is_short_name`), so it is safe
/// in paths and commands. Read from text only through that rule, a policy's
/// `[secrets.agents.<agent>]` included.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentName(String);

impl TryFrom<String> for AgentName {
    type Error = InvalidAgentName;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<AgentName> for String {
    fn from(name: AgentName) -> String {
        name.0
    }
}

impl std::borrow::Borrow<str> for AgentName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a valid agent name: use a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens, such as `main`"
)]
pub struct InvalidAgentName(pub String);

impl AgentName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AgentName {
    type Err = InvalidAgentName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match is_short_name(s) {
            true => Ok(AgentName(s.to_owned())),
            false => Err(InvalidAgentName(s.to_owned())),
        }
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub name: AgentName,
    pub created_at: Timestamp,
}

/// Bounded initial instructions for a newly created runtime profile.
/// Existing profiles are never changed through the Create action.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentInstructions(String);

impl fmt::Debug for AgentInstructions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentInstructions")
            .field("bytes", &self.0.len())
            .finish()
    }
}

pub const MAX_AGENT_INSTRUCTIONS_BYTES: usize = 8192;

impl AgentInstructions {
    pub fn new(text: String) -> Result<Self, String> {
        if text.len() > MAX_AGENT_INSTRUCTIONS_BYTES {
            return Err(format!(
                "agent instructions must be at most {MAX_AGENT_INSTRUCTIONS_BYTES} UTF-8 bytes"
            ));
        }
        if text.trim().is_empty() || text.contains('\0') {
            return Err("agent instructions must contain text and no NUL characters".to_owned());
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse() {
        for ok in ["main", "ab", "a-1", &"a".repeat(41)] {
            assert!(ok.parse::<AgentName>().is_ok(), "{ok}");
        }
        for bad in [
            "",
            "m",
            "Main",
            "a/b",
            "../x",
            "a;b",
            "a b",
            "$(x)",
            "-a",
            "a_b",
            "a.b",
            &"a".repeat(42),
        ] {
            assert!(bad.parse::<AgentName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn initial_instructions_are_bounded_as_utf8_without_changing_the_text() {
        let text = "# Voice\nBe direct. λ\n";
        assert_eq!(AgentInstructions::new(text.into()).unwrap().as_str(), text);
        assert!(
            !format!("{:?}", AgentInstructions::new(text.into()).unwrap()).contains("Be direct")
        );
        assert!(AgentInstructions::new("a".repeat(MAX_AGENT_INSTRUCTIONS_BYTES)).is_ok());
        assert!(AgentInstructions::new("λ".repeat(MAX_AGENT_INSTRUCTIONS_BYTES / 2)).is_ok());
        for invalid in [
            "".into(),
            " \n\t".into(),
            "a\0b".into(),
            "a".repeat(MAX_AGENT_INSTRUCTIONS_BYTES + 1),
            "λ".repeat(MAX_AGENT_INSTRUCTIONS_BYTES / 2 + 1),
        ] {
            assert!(AgentInstructions::new(invalid).is_err());
        }
    }
}
