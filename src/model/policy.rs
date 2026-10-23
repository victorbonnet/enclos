//! Policy models: what a sandbox may do (design §7, ADRs 0008, 0015, 0018).
//!
//! The filesystem, network, secrets and resources sections so far. `[exec]`
//! arrives with the work that enforces it.

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
    /// Secrets every session and service of the sandbox receives, by the
    /// environment variable each is set as (ADR 0022). Left out of the
    /// snapshot when empty, so a policy without any resolves as it did
    /// before secrets existed.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secrets: std::collections::BTreeMap<String, super::secret::SecretGrant>,
    /// Limits on each process of the sandbox, fixed when it starts. Left
    /// out of the snapshot when none is set, as secrets are.
    #[serde(default, skip_serializing_if = "Resources::is_unset")]
    pub resources: Resources,
}

/// Limits on a sandbox (design §7): `open_files`, `file_size` and
/// `cpu_seconds` on each of its processes, `memory` and `cpu` on the
/// sandbox as a whole. The Seatbelt backend enforces `open_files`, through
/// the process limits macOS keeps, and refuses the others (ADR 0033), so a
/// policy it stores holds none of them; `memory` and `cpu` are kept as
/// written for that refusal, and for a backend that enforces them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// The most file descriptors (files, sockets, pipes) a process holds at
    /// once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_files: Option<u64>,
    /// The largest file a process writes, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<ByteSize>,
    /// The most CPU time a process uses, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    /// A memory limit, as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// A share of CPU cores, as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
}

impl Resources {
    pub fn is_unset(&self) -> bool {
        *self == Resources::default()
    }
}

/// A size in bytes, written `1048576` (a number or text), `512K`, `100M`
/// or `2G` (powers of 1024).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "SizeText", into = "String")]
pub struct ByteSize(pub u64);

/// How a size is written: a number of bytes, or text.
#[derive(Deserialize)]
#[serde(
    untagged,
    expecting = "a size: a whole number of bytes, or one ending in K, M or G, such as \"512M\""
)]
enum SizeText {
    Bytes(u64),
    Text(String),
}

impl TryFrom<SizeText> for ByteSize {
    type Error = InvalidByteSize;

    fn try_from(size: SizeText) -> Result<Self, Self::Error> {
        match size {
            SizeText::Bytes(bytes) => Ok(ByteSize(bytes)),
            SizeText::Text(text) => text.parse(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a size: write a number of bytes, or one ending in K, M or G, such as `512M`")]
pub struct InvalidByteSize(pub String);

impl FromStr for ByteSize {
    type Err = InvalidByteSize;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidByteSize(s.to_owned());
        let (number, unit) = match s.char_indices().last() {
            Some((at, unit @ ('K' | 'M' | 'G'))) => (&s[..at], unit),
            _ => (s, 'B'),
        };
        let shift = match unit {
            'K' => 10,
            'M' => 20,
            'G' => 30,
            _ => 0,
        };
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
        let n: u64 = number.parse().map_err(|_| invalid())?;
        n.checked_mul(1 << shift).map(ByteSize).ok_or_else(invalid)
    }
}

impl TryFrom<String> for ByteSize {
    type Error = InvalidByteSize;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ByteSize> for String {
    fn from(size: ByteSize) -> String {
        size.to_string()
    }
}

impl fmt::Display for ByteSize {
    /// The largest unit that writes it whole.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        let text = match bytes {
            0 => "0".to_owned(),
            b if b.is_multiple_of(1 << 30) => format!("{}G", b >> 30),
            b if b.is_multiple_of(1 << 20) => format!("{}M", b >> 20),
            b if b.is_multiple_of(1 << 10) => format!("{}K", b >> 10),
            b => b.to_string(),
        };
        f.pad(&text)
    }
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
    /// Whether the sandbox may bind and accept TCP on any port but enclos's
    /// proxy range (ADR 0028), for a runtime whose service listens, such as
    /// Hermes's gateway. Nothing holds a listener to loopback: what listens
    /// in the sandbox can serve the network.
    #[serde(default)]
    pub listen: bool,
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
    /// The sandbox's `policy.toml` it was resolved from, whose SHA-256
    /// `inputs.overrides` holds: what `policy discard` writes back.
    pub overrides: String,
}

impl PolicySnapshot {
    /// The `policy.toml` this snapshot was resolved from, if the text
    /// stored is the one its inputs name.
    pub fn overrides_text(&self) -> Option<&str> {
        (crate::policy::sha256_hex(self.overrides.as_bytes()) == self.inputs.overrides)
            .then_some(self.overrides.as_str())
    }
}

impl Policy {
    /// Whether `self` and `other` have the same rules a session keeps from
    /// its start: files and listening, which its compiled policy holds, the
    /// secrets it is given and the limits it starts under (design §7). The
    /// rest is the proxy's, which applies it live.
    pub fn same_at_launch(&self, other: &Policy) -> bool {
        self.fs == other.fs
            && self.net.listen == other.net.listen
            && self.secrets == other.secrets
            && self.resources == other.resources
    }
}

/// A sandbox's pending policy: a snapshot saved because the user declined
/// the restart it needs. It applies to nothing until `policy apply`
/// (design §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPolicy {
    pub snapshot: SnapshotId,
    pub by: Actor,
    pub at: Timestamp,
    /// The version it restores, when it is a rollback.
    pub restores: Option<u32>,
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
    fn sizes_read_back_as_they_were_written() {
        for bytes in [0, 1, 1023, 1024, 1536, 1 << 20, 3 << 30, u64::MAX] {
            let size = ByteSize(bytes);
            assert_eq!(size.to_string().parse::<ByteSize>(), Ok(size), "{bytes}");
        }
        assert_eq!("512K".parse::<ByteSize>(), Ok(ByteSize(512 << 10)));
        for bad in [
            "",
            "K",
            "1m",
            "1.5G",
            " 1G",
            "1KB",
            "-1",
            "17179869184G",
            "18446744073709551616",
        ] {
            assert!(bad.parse::<ByteSize>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_rules_a_session_keeps_from_its_start_are_its_files_listening_secrets_and_limits() {
        let old = Policy::default();
        let mut limits = old.clone();
        limits.resources.cpu_seconds = Some(60);
        assert!(!old.same_at_launch(&limits));
        let mut net = old.clone();
        net.net.allow.push("a.example.com".into());
        net.net.mode = NetMode::Public;
        assert!(old.same_at_launch(&net));
        let mut writes = old.clone();
        writes.fs.write.push("~/work".into());
        assert!(!old.same_at_launch(&writes));
        let mut listens = old.clone();
        listens.net.listen = true;
        assert!(!old.same_at_launch(&listens));
    }

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
