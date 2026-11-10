//! How devices reach the bridge, which listens on the host's loopback only
//! (ADR 0042, proposed). The transport puts the bridge on a network the
//! person's devices are on, and says who each caller is. Tailscale is the
//! only one for now: `tailscale serve` forwards to the loopback and adds the
//! caller's tailnet login and address, and `tailscale whois` names the
//! caller's node.

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

    /// The header the transport adds with the caller's address on the
    /// network, which [`Transport::whois`] takes.
    pub fn address_header(self) -> &'static str {
        match self {
            // `tailscale serve` proxies over HTTP, and says who it proxies for
            Transport::Tailscale => "X-Forwarded-For",
        }
    }

    /// Who is at `address` on the network, as the transport knows them: the
    /// person and the node.
    pub fn whois(self, address: &str) -> Result<Caller, String> {
        match self {
            Transport::Tailscale => tailscale_whois(address),
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

/// Who calls the bridge, as the transport knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The person's login.
    pub login: String,
    /// The node's id, which stays the same when the node is renamed.
    pub node_id: String,
    /// The node's name, for people to read.
    pub node: String,
}

/// The caller's address in the transport's address header: the last one,
/// which the transport's proxy adds after any the caller sent itself.
pub fn caller_address(header: &str) -> Option<String> {
    let last = header.rsplit(',').next()?.trim();
    // An address, not anything else a command could take for an option
    let ip = last
        .parse::<std::net::IpAddr>()
        .or_else(|_| last.parse::<std::net::SocketAddr>().map(|a| a.ip()))
        .ok()?;
    Some(ip.to_string())
}

/// The `tailscale` command: the one on the PATH, else the Mac app's own.
fn tailscale_commands() -> Vec<&'static str> {
    let mut commands = vec!["tailscale"];
    if Path::new(TAILSCALE_MAC_APP).exists() {
        commands.push(TAILSCALE_MAC_APP);
    }
    commands
}

/// `tailscale whois --json <address>`.
fn tailscale_whois(address: &str) -> Result<Caller, String> {
    let mut why = "no `tailscale` command".to_owned();
    for command in tailscale_commands() {
        match std::process::Command::new(command)
            .args(["whois", "--json", address])
            .output()
        {
            Ok(out) if out.status.success() => {
                return whois_caller(&out.stdout)
                    .ok_or_else(|| "cannot read `tailscale whois`'s answer".to_owned());
            }
            Ok(out) => {
                why = format!(
                    "`tailscale whois {address}` failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => why = format!("cannot run `{command}`: {e}"),
        }
    }
    Err(why)
}

/// The caller in `tailscale whois --json`'s output: `UserProfile.LoginName`,
/// `Node.StableID` and the node's name.
fn whois_caller(answer: &[u8]) -> Option<Caller> {
    let answer: serde_json::Value = serde_json::from_slice(answer).ok()?;
    let node = answer.get("Node")?;
    let text = |value: Option<&serde_json::Value>| {
        value
            .and_then(|v| v.as_str())
            .map(|v| v.trim_end_matches('.').to_owned())
            .filter(|v| !v.is_empty())
    };
    Some(Caller {
        login: text(answer.get("UserProfile")?.get("LoginName"))?,
        node_id: text(node.get("StableID"))?,
        node: text(node.get("ComputedName")).or_else(|| text(node.get("Name")))?,
    })
}

/// `https://<host>.<tailnet>.ts.net`, from `tailscale status --json`.
fn tailscale_address() -> Option<String> {
    tailscale_commands().into_iter().find_map(|command| {
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
    fn the_caller_is_the_last_address_the_proxy_added() {
        assert_eq!(caller_address("100.64.0.9").as_deref(), Some("100.64.0.9"));
        // One the caller sent itself comes first
        assert_eq!(
            caller_address("100.64.0.1, 100.64.0.9").as_deref(),
            Some("100.64.0.9")
        );
        assert_eq!(
            caller_address("[fd7a:115c:a1e0::9]:41000").as_deref(),
            Some("fd7a:115c:a1e0::9")
        );
        assert_eq!(caller_address("--help"), None);
        assert_eq!(caller_address(""), None);
    }

    #[test]
    fn whois_names_the_person_and_the_node() {
        let answer = br#"{
            "Node": {"ID": 7, "StableID": "nPixel1CNTRL", "Name": "pixel.tail1234.ts.net.", "ComputedName": "pixel"},
            "UserProfile": {"ID": 3, "LoginName": "victor@example.com", "DisplayName": "Victor"}
        }"#;
        assert_eq!(
            whois_caller(answer),
            Some(Caller {
                login: "victor@example.com".into(),
                node_id: "nPixel1CNTRL".into(),
                node: "pixel".into(),
            })
        );
        let no_computed_name = br#"{"Node": {"StableID": "n1", "Name": "pixel.ts.net."}, "UserProfile": {"LoginName": "v@example.com"}}"#;
        assert_eq!(whois_caller(no_computed_name).unwrap().node, "pixel.ts.net");
        assert_eq!(whois_caller(br#"{"Node": {"StableID": "n1"}}"#), None);
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
