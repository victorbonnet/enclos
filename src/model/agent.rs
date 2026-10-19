//! Agents (design §3). An agent is a named identity of the sandbox's
//! runtime, with its own configuration, memory, skills, sessions and
//! channels. It shares the sandbox's runtime, policy, proxy and secrets. It
//! is not a process and not a permission boundary: the runtime adapter
//! decides how many processes run it, and the sandbox is the boundary.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;

/// An agent name: the sandbox naming rule, so it is safe in paths and
/// commands.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentName(String);

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
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if first_ok && rest_ok && (2..=41).contains(&s.len()) {
            Ok(AgentName(s.to_owned()))
        } else {
            Err(InvalidAgentName(s.to_owned()))
        }
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    pub name: AgentName,
    /// Its own proxy listener, so the network log is per agent.
    pub port: u16,
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse() {
        assert!("main".parse::<AgentName>().is_ok());
        for bad in ["", "m", "Main", "a/b", "../x"] {
            assert!(bad.parse::<AgentName>().is_err(), "{bad}");
        }
    }
}
