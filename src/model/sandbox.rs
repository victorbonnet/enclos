//! Sandbox models. Later issues add workspaces, the runtime and its agents.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::policy::TemplateName;

/// A sandbox name: a lowercase letter, then 1 to 40 lowercase letters, digits
/// or hyphens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxName(String);

/// A sandbox name that does not follow the naming rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a valid sandbox name: use a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens, such as `home` or `pi-bot`"
)]
pub struct InvalidName(pub String);

impl SandboxName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SandboxName {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if first_ok && rest_ok && (2..=41).contains(&s.len()) {
            Ok(SandboxName(s.to_owned()))
        } else {
            Err(InvalidName(s.to_owned()))
        }
    }
}

impl fmt::Display for SandboxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The isolation technology a sandbox is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Seatbelt,
    Bubblewrap,
    OpenShell,
    Libkrun,
}

impl BackendKind {
    pub const ALL: [BackendKind; 4] = [
        BackendKind::Seatbelt,
        BackendKind::Bubblewrap,
        BackendKind::OpenShell,
        BackendKind::Libkrun,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Seatbelt => "seatbelt",
            BackendKind::Bubblewrap => "bubblewrap",
            BackendKind::OpenShell => "openshell",
            BackendKind::Libkrun => "libkrun",
        }
    }
}

/// A backend name enclos does not know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown backend `{0}`: use one of seatbelt, bubblewrap, openshell, libkrun")]
pub struct UnknownBackend(pub String);

impl FromStr for BackendKind {
    type Err = UnknownBackend;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BackendKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == s)
            .ok_or_else(|| UnknownBackend(s.to_owned()))
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a sandbox is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxState {
    Created,
    Running,
    Stopped,
    Failed { reason: String },
}

/// What enclos records about a sandbox it created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRecord {
    pub name: SandboxName,
    pub backend: BackendKind,
    pub template: TemplateName,
    pub state: SandboxState,
    /// The first of the sandbox's block of proxy ports on localhost (design
    /// §4): the first serves sessions without an agent, the next ones its
    /// agents.
    pub port_base: u16,
    pub created_at: Timestamp,
}

/// How many localhost ports each sandbox reserves for its proxy.
pub const PORT_BLOCK: u16 = 16;
/// Where the blocks start, and the last port a block may use.
pub const PORT_FIRST: u16 = 41000;
pub const PORT_LAST: u16 = 48999;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for name in ["home", "pi-bot", "a1", &format!("a{}", "b".repeat(40))] {
            assert!(name.parse::<SandboxName>().is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "",
            "a",
            "Home",
            "1abc",
            "-ab",
            "a_b",
            "ab/c",
            &"a".repeat(42),
        ] {
            assert!(name.parse::<SandboxName>().is_err(), "{name}");
        }
    }

    #[test]
    fn backend_kind_round_trips_through_its_name() {
        for kind in BackendKind::ALL {
            assert_eq!(kind.as_str().parse::<BackendKind>(), Ok(kind));
        }
        assert!("docker".parse::<BackendKind>().is_err());
    }
}
