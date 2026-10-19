//! Runtimes (design §3): the software installed in a sandbox to run its
//! agents, such as Hermes. A sandbox holds at most one.

use std::fmt;
use std::str::FromStr;

/// The runtimes enclos knows. Milestone 1 has Hermes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    Hermes,
}

impl RuntimeKind {
    pub const ALL: [RuntimeKind; 1] = [RuntimeKind::Hermes];

    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeKind::Hermes => "hermes",
        }
    }
}

impl fmt::Display for RuntimeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown runtime `{0}`: this enclos knows hermes")]
pub struct UnknownRuntime(pub String);

impl FromStr for RuntimeKind {
    type Err = UnknownRuntime;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RuntimeKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| UnknownRuntime(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse() {
        assert_eq!("hermes".parse::<RuntimeKind>(), Ok(RuntimeKind::Hermes));
        assert!("claude".parse::<RuntimeKind>().is_err());
    }
}
