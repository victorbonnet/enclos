//! Network log models: one record per connection the proxy handled
//! (design §6). For HTTPS that is one tunnel; the proxy never sees the
//! requests inside it.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::sandbox::SandboxName;

/// What the proxy did with a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Denied,
}

/// Why a connection was denied or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The destination is not on the allowlist.
    NotAllowed,
    /// Every address it resolved to is never reachable (ADR 0017).
    BlockedAddress,
    /// It resolved to private addresses and the policy has no opt-in for it.
    PrivateAddress,
    /// The name did not resolve.
    ResolveFailed,
    /// No validated address accepted the connection.
    ConnectFailed,
    /// The client did not send a request the proxy understands.
    BadRequest,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::NotAllowed => "not-allowed",
            Reason::BlockedAddress => "blocked-address",
            Reason::PrivateAddress => "private-address",
            Reason::ResolveFailed => "resolve-failed",
            Reason::ConnectFailed => "connect-failed",
            Reason::BadRequest => "bad-request",
        }
    }

    const ALL: [Reason; 6] = [
        Reason::NotAllowed,
        Reason::BlockedAddress,
        Reason::PrivateAddress,
        Reason::ResolveFailed,
        Reason::ConnectFailed,
        Reason::BadRequest,
    ];
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Reason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Reason::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("unknown reason `{s}`"))
    }
}

/// One connection through a sandbox's proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub at: Timestamp,
    pub sandbox: SandboxName,
    /// The agent whose listener took the connection; attribution is
    /// informative, not a boundary (ADR 0003).
    pub agent: Option<String>,
    /// The host and port asked for.
    pub host: String,
    pub port: u16,
    /// `CONNECT` for a tunnel, else the plain-HTTP method.
    pub method: String,
    /// The address actually connected to, when one was.
    pub address: Option<String>,
    pub verdict: Verdict,
    pub reason: Option<Reason>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
}

/// One destination the proxy refused, with how often and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedDestination {
    pub host: String,
    pub port: u16,
    pub reason: Reason,
    pub count: u64,
    pub first: Timestamp,
    pub last: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_round_trip_through_their_names() {
        for reason in Reason::ALL {
            assert_eq!(reason.as_str().parse::<Reason>(), Ok(reason));
        }
    }
}
