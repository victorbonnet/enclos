//! Sandbox models. Later issues add workspaces, the runtime and its agents.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::policy::TemplateName;
use super::runtime::RuntimeKind;

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

/// The naming rule sandboxes and agents share: a lowercase letter, then 1
/// to 40 lowercase letters, digits or hyphens. Safe in a path, as one shell
/// word, and never read as a flag.
pub const fn is_short_name(s: &str) -> bool {
    // Const, so a name written in code is checked when it compiles.
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 41 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

impl FromStr for SandboxName {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match is_short_name(s) {
            true => Ok(SandboxName(s.to_owned())),
            false => Err(InvalidName(s.to_owned())),
        }
    }
}

impl fmt::Display for SandboxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
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
        f.pad(self.as_str())
    }
}

/// Where a sandbox is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
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
    /// The sandbox's proxy port on loopback (design §4), reserved when it
    /// is created.
    pub proxy_port: u16,
    /// The runtime installed in it, if any (at most one, ADR 0003).
    pub runtime: Option<RuntimeKind>,
    pub created_at: Timestamp,
}

/// The range sandbox proxy ports are taken from.
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

    #[test]
    fn names_and_backends_honor_a_table_width() {
        let name: SandboxName = "home".parse().unwrap();
        assert_eq!(format!("{name:<6}|"), "home  |");
        assert_eq!(format!("{:<10}|", BackendKind::Seatbelt), "seatbelt  |");
    }
}
