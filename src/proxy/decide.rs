//! The proxy's decisions, as pure functions (ADRs 0007, 0017): whether a
//! destination is on the allowlist, and which of its resolved addresses may
//! be connected to.

use std::net::IpAddr;

use crate::model::net::Reason;
use crate::model::policy::Policy;
use crate::net::addr::AddrClass;
use crate::net::host::{AllowEntry, normalize_host};

/// A destination as the client asked for it, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// A lowercase host name, or an IP address in its usual text form.
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
}

impl Destination {
    pub fn parse(host: &str, port: u16) -> Result<Destination, Reason> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(Destination {
                host: ip.to_string(),
                ip: Some(ip),
                port,
            });
        }
        let host = normalize_host(host).map_err(|_| Reason::BadRequest)?;
        Ok(Destination {
            host,
            ip: None,
            port,
        })
    }
}

/// Whether the allowlist lets the sandbox reach `dest`.
pub fn allowed(policy: &Policy, dest: &Destination) -> bool {
    policy
        .net
        .allow
        .iter()
        .filter_map(|entry| AllowEntry::parse(entry).ok())
        .any(|entry| entry.matches(&dest.host, dest.port))
}

/// The addresses the proxy may connect to, in the order given: global ones,
/// and private ones only when the policy opts in for this host. When none
/// remains, why.
pub fn validated(
    policy: &Policy,
    dest: &Destination,
    resolved: &[IpAddr],
    classify: fn(IpAddr) -> AddrClass,
) -> Result<Vec<IpAddr>, Reason> {
    let opted_in = policy.net.private.contains(&dest.host);
    let mut saw_private = false;
    let ok: Vec<IpAddr> = resolved
        .iter()
        .copied()
        .filter(|ip| match classify(*ip) {
            AddrClass::Global => true,
            AddrClass::Private => {
                saw_private = true;
                opted_in
            }
            AddrClass::Blocked(_) => false,
        })
        .collect();
    match (ok.is_empty(), saw_private) {
        (false, _) => Ok(ok),
        (true, true) => Err(Reason::PrivateAddress),
        (true, false) => Err(Reason::BlockedAddress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::addr::classify;

    fn policy(allow: &[&str], private: &[&str]) -> Policy {
        let mut p = Policy::default();
        p.net.allow = allow.iter().map(|s| s.to_string()).collect();
        p.net.private = private.iter().map(|s| s.to_string()).collect();
        p
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn only_listed_destinations_and_ports_are_allowed() {
        let p = policy(
            &[
                "api.example.com",
                "*.cdn.example.net",
                "files.example.org:8443",
            ],
            &[],
        );
        let dest = |h: &str, port| Destination::parse(h, port).unwrap();
        assert!(allowed(&p, &dest("API.example.com.", 443)));
        assert!(allowed(&p, &dest("a.cdn.example.net", 443)));
        assert!(allowed(&p, &dest("files.example.org", 8443)));
        assert!(!allowed(&p, &dest("api.example.com", 80)));
        assert!(!allowed(&p, &dest("evil.example.com", 443)));
        assert!(!allowed(&p, &dest("cdn.example.net", 443)));
    }

    #[test]
    fn a_name_resolving_to_blocked_addresses_is_refused() {
        let p = policy(&["rebind.example.com"], &[]);
        let dest = Destination::parse("rebind.example.com", 443).unwrap();
        let blocked = ips(&["127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"]);
        assert_eq!(
            validated(&p, &dest, &blocked, classify),
            Err(Reason::BlockedAddress)
        );
        // Mixed answers keep only the global addresses, in order.
        let mixed = ips(&["127.0.0.1", "93.184.216.34", "10.0.0.1", "2606:4700::1111"]);
        assert_eq!(
            validated(&p, &dest, &mixed, classify),
            Ok(ips(&["93.184.216.34", "2606:4700::1111"]))
        );
    }

    #[test]
    fn private_answers_need_the_opt_in_for_that_host() {
        let dest = Destination::parse("printer.lan", 443).unwrap();
        let answer = ips(&["192.168.1.20"]);
        let without = policy(&["printer.lan"], &[]);
        assert_eq!(
            validated(&without, &dest, &answer, classify),
            Err(Reason::PrivateAddress)
        );
        let with = policy(&["printer.lan"], &["printer.lan"]);
        assert_eq!(
            validated(&with, &dest, &answer, classify),
            Ok(answer.clone())
        );
        // The opt-in never unlocks loopback.
        assert_eq!(
            validated(&with, &dest, &ips(&["127.0.0.1"]), classify),
            Err(Reason::BlockedAddress)
        );
    }
}
