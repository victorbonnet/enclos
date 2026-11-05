//! How devices reach the bridge, which listens on the host's loopback only
//! (ADR 0042, proposed). The transport puts the bridge on a network the
//! person's devices are on, and says who each caller is. Tailscale is the
//! only one for now: `tailscale serve` forwards to the loopback and adds the
//! caller's tailnet login.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

/// The transports enclos knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tailscale,
}

/// Where the Mac app keeps its command, which it puts on no PATH.
const TAILSCALE_MAC_APP: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";

impl Transport {
    pub const ALL: [Transport; 1] = [Transport::Tailscale];

    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tailscale => "tailscale",
        }
    }

    /// The header the transport adds with the caller's login, which the
    /// bridge takes as the person speaking.
    pub fn login_header(self) -> &'static str {
        match self {
            Transport::Tailscale => "Tailscale-User-Login",
        }
    }

    /// Why a connection without that header is refused.
    pub fn no_login(self) -> &'static str {
        match self {
            Transport::Tailscale => {
                "no Tailscale login: reach the bridge through `tailscale serve`"
            }
        }
    }

    /// The command that puts the bridge's loopback port on the network.
    pub fn expose_hint(self, port: u16) -> String {
        match self {
            Transport::Tailscale => format!("tailscale serve --bg {port}"),
        }
    }

    /// The bridge's address on the network, for the pairing link; `None`
    /// when it cannot be read, so the user gives it.
    pub fn address(self) -> Option<String> {
        match self {
            Transport::Tailscale => tailscale_address(),
        }
    }

    /// What the address looks like, for the message asking for it.
    pub fn address_form(self) -> &'static str {
        match self {
            Transport::Tailscale => "https://<host>.<tailnet>.ts.net",
        }
    }
}

/// `https://<host>.<tailnet>.ts.net`, from `tailscale status --json`: the
/// command on the PATH, else the Mac app's own.
fn tailscale_address() -> Option<String> {
    let mut commands = vec!["tailscale"];
    if Path::new(TAILSCALE_MAC_APP).exists() {
        commands.push(TAILSCALE_MAC_APP);
    }
    commands.into_iter().find_map(|command| {
        let out = std::process::Command::new(command)
            .args(["status", "--json"])
            .output()
            .ok()?;
        dns_name_url(&out.stdout)
    })
}

/// The address in `tailscale status --json`'s output, from `Self.DNSName`.
fn dns_name_url(status: &[u8]) -> Option<String> {
    let status: serde_json::Value = serde_json::from_slice(status).ok()?;
    let name = status.get("Self")?.get("DNSName")?.as_str()?;
    let name = name.trim_end_matches('.');
    (!name.is_empty()).then(|| format!("https://{name}"))
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown transport `{0}`: this enclos knows {known}", known = known())]
pub struct UnknownTransport(pub String);

fn known() -> String {
    Transport::ALL
        .iter()
        .map(|t| t.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl FromStr for Transport {
    type Err = UnknownTransport;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Transport::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| UnknownTransport(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transports_parse_and_name_their_header() {
        assert_eq!("tailscale".parse::<Transport>(), Ok(Transport::Tailscale));
        assert!("wireguard".parse::<Transport>().is_err());
        assert_eq!(Transport::Tailscale.login_header(), "Tailscale-User-Login");
        assert_eq!(
            Transport::Tailscale.expose_hint(47100),
            "tailscale serve --bg 47100"
        );
    }

    #[test]
    fn the_address_is_the_dns_name_without_its_dot() {
        let status = br#"{"Self": {"DNSName": "mac.tail1234.ts.net."}}"#;
        assert_eq!(
            dns_name_url(status).as_deref(),
            Some("https://mac.tail1234.ts.net")
        );
        assert_eq!(dns_name_url(br#"{"Self": {"DNSName": ""}}"#), None);
        assert_eq!(dns_name_url(b"not json"), None);
    }
}
