//! Network allowlist entries: `host`, `host:port`, `*.domain[:port]`, or an
//! IP literal (`1.2.3.4`, `[2001:db8::1]:8443`). Without a port, 443.
//!
//! Hosts are normalized the way the proxy compares them: lowercase, no
//! trailing dot, ASCII only (an international name is written in its
//! `xn--` form).

use std::fmt;
use std::net::IpAddr;

use super::addr::{AddrClass, classify};

pub const DEFAULT_PORT: u16 = 443;

/// What an allowlist entry matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostPattern {
    /// This host only.
    Exact(String),
    /// Every subdomain of this domain, not the domain itself.
    Subdomains(String),
    /// This address only.
    Ip(IpAddr),
}

/// Why an entry is not accepted. A policy whose problems are all refusals
/// exits 2 (design §10); one malformed entry makes it exit 1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    /// It is not written as a destination: fix how it is written.
    #[error("{0}")]
    Malformed(String),
    /// A destination enclos never allows: loopback, link-local, localhost,
    /// every destination (`*`) or a wildcard over a public suffix.
    #[error("{0}")]
    Refused(String),
}

impl EntryError {
    pub fn is_refused(&self) -> bool {
        matches!(self, EntryError::Refused(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllowEntry {
    pub host: HostPattern,
    pub port: u16,
}

impl AllowEntry {
    /// Parses and checks one entry; the error says what is wrong with it and
    /// whether it is a refusal.
    pub fn parse(entry: &str) -> Result<AllowEntry, EntryError> {
        let entry = entry.trim();
        let (host, port) = split_port(entry).map_err(EntryError::Malformed)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let AddrClass::Blocked(why) = classify(ip) {
                return Err(EntryError::Refused(format!(
                    "{ip} is a {why} address, which is never reachable"
                )));
            }
            return Ok(AllowEntry {
                host: HostPattern::Ip(ip),
                port,
            });
        }
        if host == "*" {
            return Err(EntryError::Refused(
                "* would allow every destination; name a domain someone owns, such as *.example.com"
                    .to_owned(),
            ));
        }
        if let Some(domain) = host.strip_prefix("*.") {
            // The syntax first, so a typo is not taken for a public suffix.
            // Then a public suffix (com, co.uk, githubusercontent.com) is
            // refused before the full-name check would call `com` malformed:
            // its subdomains belong to everyone.
            let domain = host_syntax(domain)?;
            refuse_localhost(&domain)?;
            if psl::domain_str(&domain).is_none() {
                return Err(EntryError::Refused(format!(
                    "*.{domain} would allow a whole public suffix; name a domain someone owns, such as *.example.com"
                )));
            }
            full_domain(&domain)?;
            return Ok(AllowEntry {
                host: HostPattern::Subdomains(domain),
                port,
            });
        }
        if host.contains('*') {
            return Err(EntryError::Malformed(
                "a wildcard may only cover subdomains, written *.example.com".to_owned(),
            ));
        }
        let host = normalize_host(host)?;
        Ok(AllowEntry {
            host: HostPattern::Exact(host),
            port,
        })
    }

    /// Whether a connection to `host` (already normalized) and `port` matches.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        match &self.host {
            HostPattern::Exact(exact) => host == exact,
            HostPattern::Subdomains(domain) => host
                .strip_suffix(domain.as_str())
                .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1),
            HostPattern::Ip(ip) => host.parse::<IpAddr>().is_ok_and(|h| h == *ip),
        }
    }

    /// The host part as written in a policy, without the port.
    pub fn host_text(&self) -> String {
        match &self.host {
            HostPattern::Exact(h) => h.clone(),
            HostPattern::Subdomains(d) => format!("*.{d}"),
            HostPattern::Ip(ip) => ip.to_string(),
        }
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = match &self.host {
            HostPattern::Ip(IpAddr::V6(ip)) if self.port != DEFAULT_PORT => format!("[{ip}]"),
            _ => self.host_text(),
        };
        if self.port == DEFAULT_PORT {
            f.write_str(&host)
        } else {
            write!(f, "{host}:{}", self.port)
        }
    }
}

fn split_port(entry: &str) -> Result<(&str, u16), String> {
    let port = |p: &str| {
        p.parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("`{p}` is not a port: use 1 to 65535"))
    };
    if let Some(rest) = entry.strip_prefix('[') {
        let (ip, after) = rest
            .split_once(']')
            .ok_or("an IPv6 address in [ ] is missing its ]")?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((ip, port(p)?)),
            None if after.is_empty() => Ok((ip, DEFAULT_PORT)),
            None => Err(format!("unexpected `{after}` after the address")),
        };
    }
    // A bare IPv6 address has several colons and no port.
    if entry.matches(':').count() > 1 {
        return Ok((entry, DEFAULT_PORT));
    }
    match entry.rsplit_once(':') {
        Some((host, p)) => Ok((host, port(p)?)),
        None => Ok((entry, DEFAULT_PORT)),
    }
}

/// A `network.private` entry in the form the allowlist and the proxy compare
/// against: an IP address as Rust prints it, or a normalized host name.
pub fn canonical_private(entry: &str) -> Result<String, EntryError> {
    match entry.parse::<IpAddr>() {
        Ok(ip) => Ok(ip.to_string()),
        Err(_) => normalize_host(entry),
    }
}

/// Lowercases a host name, drops a trailing dot, and checks it is a full
/// domain name: dot-separated labels of letters, digits and hyphens.
/// `localhost` and its subdomains are refused; any other problem is
/// malformed.
pub fn normalize_host(host: &str) -> Result<String, EntryError> {
    let host = host_syntax(host)?;
    refuse_localhost(&host)?;
    full_domain(&host)?;
    Ok(host)
}

/// The host lowercased, without a trailing dot, if it is written as
/// dot-separated labels of letters, digits and hyphens.
fn host_syntax(host: &str) -> Result<String, EntryError> {
    let malformed = |why: String| Err(EntryError::Malformed(why));
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return malformed("the host is empty".to_owned());
    }
    if !host.is_ascii() {
        return malformed(format!(
            "`{host}` is not ASCII: write an international name in its xn-- form"
        ));
    }
    if host.len() > 253 {
        return malformed("the host is longer than 253 characters".to_owned());
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !host.split('.').all(label_ok) {
        return malformed(format!("`{host}` is not a host name"));
    }
    Ok(host)
}

/// Checked before the full-name check, so a bare `localhost` is refused
/// rather than malformed.
fn refuse_localhost(host: &str) -> Result<(), EntryError> {
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(EntryError::Refused(
            "localhost is never reachable from a sandbox".to_owned(),
        ));
    }
    Ok(())
}

/// A name with a dot whose last label is not a number.
fn full_domain(host: &str) -> Result<(), EntryError> {
    if !host.contains('.') {
        return Err(EntryError::Malformed(format!(
            "`{host}` is not a full domain name, such as api.example.com"
        )));
    }
    // No top-level domain is a number. A resolver reads `127.1`, `0x7f.1` or
    // `0177.0.0.1` as an IPv4 address, so these would get past the checks on
    // IP literals.
    let last = host.rsplit('.').next().unwrap_or_default();
    let hex = last.strip_prefix("0x").unwrap_or(last);
    if last.bytes().all(|b| b.is_ascii_digit())
        || (last.starts_with("0x") && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(EntryError::Malformed(format!(
            "`{host}` reads as an IP address: write an IPv4 address as four decimal numbers, such as 192.0.2.10"
        )));
    }
    Ok(())
}

/// The host an allowlist entry names, in the form `canonical_private`
/// gives, whether or not the entry is accepted: `network.private` is checked
/// against what the user listed, not only against what was allowed.
pub fn listed_host(entry: &str) -> Option<String> {
    let (host, _) = split_port(entry.trim()).ok()?;
    canonical_private(host).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(entry: &str) -> AllowEntry {
        AllowEntry::parse(entry).unwrap_or_else(|e| panic!("{entry}: {e}"))
    }

    #[test]
    fn hosts_ports_and_wildcards_parse_and_normalize() {
        assert_eq!(ok("API.OpenAI.com.").to_string(), "api.openai.com");
        assert_eq!(ok("example.com:8443").port, 8443);
        assert_eq!(
            ok("*.openai.com").host,
            HostPattern::Subdomains("openai.com".into())
        );
        assert_eq!(ok("1.1.1.1").port, 443);
        assert_eq!(
            ok("[2606:4700::1111]:8443").to_string(),
            "[2606:4700::1111]:8443"
        );
        assert_eq!(ok("2606:4700::1111").port, 443);
    }

    #[test]
    fn destinations_a_sandbox_may_never_reach_are_refused() {
        for bad in [
            "*",
            "*:8443",
            // githubusercontent.com is on the Public Suffix List: each subdomain is someone else's.
            "*.com",
            "*.com.",
            "*.co.uk",
            "*.githubusercontent.com",
            "localhost",
            "api.localhost",
            "*.localhost",
            "127.0.0.1",
            "[::1]:443",
            "169.254.169.254",
            // IPv6 that is not global unicast.
            "[64:ff9b:1::1]:443",
            "100:0:0:1::1",
            "4000::1",
        ] {
            let err = AllowEntry::parse(bad).unwrap_err();
            assert!(err.is_refused(), "{bad}: {err}");
        }
        assert_eq!(
            AllowEntry::parse("4000::1").unwrap_err().to_string(),
            "4000::1 is a reserved IPv6 address, which is never reachable"
        );
    }

    #[test]
    fn entries_that_are_not_destinations_are_malformed() {
        for bad in [
            "a*.example.com",
            // A wildcard over a name that does not parse is a typo, not a
            // public suffix.
            "*.",
            "*.*",
            "*.a b",
            "*.-bad",
            "*.a_b",
            "*.ünïcode",
            // The default PSL rule makes 127.1 registrable, so the IP check
            // below the public-suffix one applies.
            "*.127.1",
            "intranet",
            "example.com:0",
            "example.com:99999",
            "exa mple.com",
            "-bad.example.com",
            "ünïcode.example",
            // IPv4 addresses in the forms a resolver also accepts.
            "127.1",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "192.168.1",
            "169.254.43518",
            "a.0x7f",
        ] {
            let err = AllowEntry::parse(bad).unwrap_err();
            assert!(!err.is_refused(), "{bad}: {err}");
        }
    }

    #[test]
    fn entries_match_host_and_port() {
        let exact = ok("api.example.com");
        assert!(exact.matches("api.example.com", 443));
        assert!(!exact.matches("api.example.com", 80));
        assert!(!exact.matches("x.api.example.com", 443));
        let sub = ok("*.example.com");
        assert!(sub.matches("a.example.com", 443));
        assert!(sub.matches("a.b.example.com", 443));
        assert!(!sub.matches("example.com", 443));
        assert!(!sub.matches("badexample.com", 443));
    }
}
