//! Policy models: what a sandbox may do (design §7, ADRs 0008, 0015, 0018).
//!
//! Milestone 1 has the filesystem and network sections. `[exec]`,
//! `[resources]` and `[secrets]` arrive with the milestones that enforce them.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::Timestamp;
use super::audit::Actor;

/// A policy with every layer applied: what a sandbox actually runs under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub fs: FsPolicy,
    pub net: NetPolicy,
}

/// Paths as written in policy files: absolute, `~/…`, or starting with the
/// `{home}` (the sandbox's home) or `{tmp}` placeholders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsPolicy {
    /// Where the sandbox may write.
    pub write: Vec<String>,
    /// What the sandbox may not read; everything else is readable (ADR 0015).
    pub read_deny: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPolicy {
    /// Which destinations are reachable at all (ADR 0025).
    pub mode: NetMode,
    /// Destinations the proxy lets through: `host`, `host:port` or
    /// `*.domain`. Without a port, 443.
    pub allow: Vec<String>,
    /// Allowed hosts that may resolve to private addresses (ADR 0017).
    pub private: Vec<String>,
    pub log: NetLog,
}

/// Which destinations a sandbox may reach (ADR 0025). Either way, every
/// connection goes through the proxy, is logged, and reaches only addresses
/// it validated (ADR 0017).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetMode {
    /// Only the destinations listed in `allow`.
    #[default]
    Allowlist,
    /// Any public address on the web ports, 80 and 443, as well as what
    /// `allow` lists.
    Public,
}

impl NetMode {
    /// The ports public mode opens to any public address.
    pub const PUBLIC_PORTS: [u16; 2] = [80, 443];

    pub fn as_str(self) -> &'static str {
        match self {
            NetMode::Allowlist => "allowlist",
            NetMode::Public => "public",
        }
    }
}

impl fmt::Display for NetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// What the network log keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetLog {
    /// Host, port, address, verdict, bytes and duration; never contents.
    #[default]
    Metadata,
}

/// The name of a template: same rule as a sandbox name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TemplateName(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a template name: use lowercase letters, digits and hyphens, such as `assistant`"
)]
pub struct InvalidTemplateName(pub String);

impl TemplateName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for TemplateName {
    type Err = InvalidTemplateName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if first_ok && rest_ok && (2..=41).contains(&s.len()) {
            Ok(TemplateName(s.to_owned()))
        } else {
            Err(InvalidTemplateName(s.to_owned()))
        }
    }
}

impl TryFrom<String> for TemplateName {
    type Error = InvalidTemplateName;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<TemplateName> for String {
    fn from(name: TemplateName) -> String {
        name.0
    }
}

impl fmt::Display for TemplateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

/// The SHA-256 of a resolved policy and its inputs, in hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

impl SnapshotId {
    /// The first 12 hex digits, enough to tell snapshots apart in output.
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(12)]
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

/// What a snapshot was resolved from, so it can be told apart from the same
/// overrides resolved against another template or enclos version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInputs {
    pub enclos_version: String,
    /// SHA-256 of the built-in defaults.
    pub defaults: String,
    pub template: TemplateName,
    /// SHA-256 of the template's content.
    pub template_hash: String,
    /// The runtime adapter's contributed endpoints, once a runtime is installed.
    pub adapter: Option<AdapterInput>,
    /// SHA-256 of the sandbox's `policy.toml`.
    pub overrides: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterInput {
    pub runtime: String,
    pub version: String,
    pub hash: String,
}

/// An immutable, fully resolved policy (ADR 0018).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub id: SnapshotId,
    pub inputs: PolicyInputs,
    pub policy: Policy,
}

/// One entry of a sandbox's append-only policy history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersion {
    pub version: u32,
    pub snapshot: SnapshotId,
    pub by: Actor,
    pub at: Timestamp,
    /// The version a rollback restored.
    pub restores: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_names_follow_the_naming_rule() {
        assert!("assistant".parse::<TemplateName>().is_ok());
        assert!("mcp-only".parse::<TemplateName>().is_ok());
        let name: TemplateName = "assistant".parse().unwrap();
        assert_eq!(format!("{name:<12}|"), "assistant   |");
        for bad in ["", "A", "1x", "a b", "../x"] {
            assert!(bad.parse::<TemplateName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn snapshot_ids_shorten_for_display() {
        let id = SnapshotId("0123456789abcdef".into());
        assert_eq!(id.short(), "0123456789ab");
    }
}
