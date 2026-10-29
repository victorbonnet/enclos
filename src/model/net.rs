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

/// Why a connection was denied or failed, or why the proxy closed one it
/// allowed.
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
    /// The proxy could not get the sandbox's active policy (`state.db`
    /// unreadable, or no active policy), so it refused the connection
    /// whatever its destination: nothing to allow.
    PolicyUnreadable,
    /// Allowed, then closed by the proxy: no byte moved either way, or a
    /// peer read nothing, for the idle limit, or the client's first bytes
    /// did not show a whole hello within 30 seconds (design §6).
    Idle,
    /// A tunnel whose TLS ClientHello asks for another server than the
    /// host it was opened for: closed by the server name check (design §6).
    NameMismatch,
    /// A tunnel whose first bytes start a TLS record, or an SSLv2-format
    /// hello, but do not read cleanly as one ClientHello within 64 KiB:
    /// closed, since a server could read a name the proxy cannot.
    HelloUnreadable,
    /// A tunnel opened for a host name whose TLS ClientHello names no
    /// server: closed, since it would reach whichever site the address
    /// serves by default (design §6). A tunnel opened for an address is not
    /// refused for this: a client names no server for an address.
    NoServerName,
    /// A tunnel whose TLS ClientHello carries Encrypted Client Hello with a
    /// visible name other than its host, or none: closed, since the name it
    /// asks for cannot be compared (design §6).
    EncryptedHello,
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
            Reason::PolicyUnreadable => "policy-unreadable",
            Reason::Idle => "idle",
            Reason::NameMismatch => "name-mismatch",
            Reason::HelloUnreadable => "hello-unreadable",
            Reason::NoServerName => "no-server-name",
            Reason::EncryptedHello => "encrypted-hello",
        }
    }

    /// Whether the refusal left nothing for `enclos policy allow` to change,
    /// because it did not depend on the destination. Every reason is listed,
    /// so a new one has to decide.
    pub fn nothing_to_allow(self) -> bool {
        match self {
            // A bad request is refused whatever the policy says, and a
            // tunnel naming another server whatever host it was opened for:
            // allowing that server lets it be reached directly, not this way.
            Reason::PolicyUnreadable
            | Reason::BadRequest
            | Reason::NameMismatch
            | Reason::HelloUnreadable
            | Reason::NoServerName
            | Reason::EncryptedHello => true,
            Reason::NotAllowed
            | Reason::BlockedAddress
            | Reason::PrivateAddress
            | Reason::ResolveFailed
            | Reason::ConnectFailed
            | Reason::Idle => false,
        }
    }

    const ALL: [Reason; 12] = [
        Reason::NotAllowed,
        Reason::BlockedAddress,
        Reason::PrivateAddress,
        Reason::ResolveFailed,
        Reason::ConnectFailed,
        Reason::BadRequest,
        Reason::PolicyUnreadable,
        Reason::Idle,
        Reason::NameMismatch,
        Reason::HelloUnreadable,
        Reason::NoServerName,
        Reason::EncryptedHello,
    ];
}

/// What the client's first bytes on a tunnel said about the server it asks
/// for, as the server name check read them (design §6). A name is the
/// client's own text, so it is kept escaped and cut to 255 characters, as a
/// host the proxy could not read is: it is shown on the host's terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameSeen {
    /// A TLS ClientHello naming a server.
    Name(String),
    /// A TLS ClientHello naming none.
    NoName,
    /// A TLS ClientHello carrying Encrypted Client Hello, whose visible
    /// name, if any, is not the tunnel's host: under ECH it is the public
    /// name of the server that decrypts the real one.
    Encrypted { public: Option<String> },
    /// Not TLS: another protocol, which the check leaves alone.
    NotTls,
    /// TLS whose first message does not read cleanly as one ClientHello.
    Unreadable,
    /// The client stopped, failed or went idle before its first bytes
    /// showed anything.
    Incomplete,
}

impl NameSeen {
    /// Its kind, as `state.db` stores it.
    pub fn as_str(&self) -> &'static str {
        match self {
            NameSeen::Name(_) => "name",
            NameSeen::NoName => "no-name",
            NameSeen::Encrypted { .. } => "encrypted",
            NameSeen::NotTls => "not-tls",
            NameSeen::Unreadable => "unreadable",
            NameSeen::Incomplete => "incomplete",
        }
    }

    /// The name it shows, if any.
    pub fn name(&self) -> Option<&str> {
        match self {
            NameSeen::Name(name) | NameSeen::Encrypted { public: Some(name) } => Some(name),
            _ => None,
        }
    }

    /// What a client's server name, as it sent it, is kept as.
    pub fn shown(name: &str) -> String {
        name.escape_default().take(255).collect()
    }

    /// From its kind and its name, as `state.db` stores them; a name where
    /// its kind has none, or none where it has one, is an error.
    pub fn from_columns(kind: &str, name: Option<String>) -> Result<NameSeen, String> {
        let nameless = |seen: NameSeen| match &name {
            None => Ok(seen),
            Some(_) => Err(format!("a server name with the outcome `{kind}`")),
        };
        match kind {
            "name" => name
                .map(NameSeen::Name)
                .ok_or_else(|| "the outcome `name` with no server name".to_owned()),
            "encrypted" => Ok(NameSeen::Encrypted { public: name }),
            "no-name" => nameless(NameSeen::NoName),
            "not-tls" => nameless(NameSeen::NotTls),
            "unreadable" => nameless(NameSeen::Unreadable),
            "incomplete" => nameless(NameSeen::Incomplete),
            other => Err(format!("unknown server name outcome `{other}`")),
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
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

/// A host and port as one destination, with an IPv6 address in brackets, so
/// that the text reads back as the same destination in `enclos policy allow`.
pub fn destination(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// One connection through a sandbox's proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub at: Timestamp,
    pub sandbox: SandboxName,
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
    /// For a tunnel, what its first bytes said about the server it asks
    /// for; none for plain HTTP, a refused request, a tunnel still open,
    /// and one whose client sent nothing.
    pub name_seen: Option<NameSeen>,
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
    fn an_ipv6_destination_is_bracketed() {
        assert_eq!(destination("2606:4700::1111", 443), "[2606:4700::1111]:443");
        assert_eq!(destination("api.example.com", 8443), "api.example.com:8443");
    }

    #[test]
    fn every_reason_is_in_all() {
        // No `_` arm: a new reason does not compile until it gets the next
        // index here, which is its place in `ALL`, the list `FromStr` reads.
        fn index(reason: Reason) -> usize {
            match reason {
                Reason::NotAllowed => 0,
                Reason::BlockedAddress => 1,
                Reason::PrivateAddress => 2,
                Reason::ResolveFailed => 3,
                Reason::ConnectFailed => 4,
                Reason::BadRequest => 5,
                Reason::PolicyUnreadable => 6,
                Reason::Idle => 7,
                Reason::NameMismatch => 8,
                Reason::HelloUnreadable => 9,
                Reason::NoServerName => 10,
                Reason::EncryptedHello => 11,
            }
        }
        for (i, reason) in Reason::ALL.into_iter().enumerate() {
            assert_eq!(index(reason), i, "{reason}");
        }
    }

    #[test]
    fn reasons_round_trip_through_their_names() {
        for reason in Reason::ALL {
            assert_eq!(reason.as_str().parse::<Reason>(), Ok(reason));
        }
        for seen in [
            NameSeen::Name("api.example.com".into()),
            NameSeen::NoName,
            NameSeen::Encrypted { public: None },
            NameSeen::Encrypted {
                public: Some("public.example.net".into()),
            },
            NameSeen::NotTls,
            NameSeen::Unreadable,
            NameSeen::Incomplete,
        ] {
            let name = seen.name().map(str::to_owned);
            assert_eq!(NameSeen::from_columns(seen.as_str(), name), Ok(seen));
        }
        assert!(NameSeen::from_columns("name", None).is_err());
        assert!(NameSeen::from_columns("not-tls", Some("x".into())).is_err());
        assert!(NameSeen::from_columns("other", None).is_err());
    }

    #[test]
    fn a_server_name_is_kept_escaped_and_cut() {
        assert_eq!(
            NameSeen::shown("evil\u{1b}[2J\nexample.com"),
            "evil\\u{1b}[2J\\nexample.com"
        );
        assert_eq!(NameSeen::shown(&"a".repeat(300)).len(), 255);
    }
}
