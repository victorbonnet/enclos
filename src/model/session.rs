//! Sessions and their members (design §8, ADR 0019): one run inside a
//! sandbox, with every process it started, and the policy it started under.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::policy::SnapshotId;
use super::sandbox::SandboxName;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub i64);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// `enclos connect`, in the user's terminal.
    Interactive,
    /// An agent running as a background service.
    Service,
    /// The sandbox's egress proxy, outside the sandbox.
    Proxy,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::Interactive => "interactive",
            SessionKind::Service => "service",
            SessionKind::Proxy => "proxy",
        }
    }
}

impl FromStr for SessionKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [
            SessionKind::Interactive,
            SessionKind::Service,
            SessionKind::Proxy,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
        .ok_or_else(|| format!("unknown session kind `{s}`"))
    }
}

/// A process enclos started, as it can be recognized later: its pid alone
/// could have been reused, so its start time is kept too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    /// The start time `ps` reports for it, compared as text.
    pub started: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: SessionId,
    pub sandbox: SandboxName,
    pub agent: Option<String>,
    pub kind: SessionKind,
    /// The policy version and snapshot the session started under.
    pub version: u32,
    pub snapshot: SnapshotId,
    /// The compiled policy file it runs under (none for the proxy).
    pub compiled: Option<String>,
    /// The first process of the session.
    pub root: ProcessRef,
    /// The process group its members share.
    pub pgid: u32,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
}

/// A process found running in a session's process group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub pid: u32,
    pub started: String,
    pub command: String,
}
