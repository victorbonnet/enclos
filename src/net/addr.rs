//! Which addresses the proxy may connect to (ADR 0017).
//!
//! Every IANA IPv4 and IPv6 special-purpose block that is not globally
//! reachable is refused, except the private ranges, which a policy's
//! `private` opt-in unlocks for named hosts. IPv6 forms that carry an IPv4
//! address (mapped, NAT64, 6to4, Teredo) are judged by that address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What an address is, for the proxy's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    /// Reachable on the internet.
    Global,
    /// RFC 1918, carrier-grade NAT or unique-local IPv6: only with the
    /// `private` opt-in.
    Private,
    /// Never reachable, whatever the policy says.
    Blocked(&'static str),
}

pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

pub fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    // Globally reachable exceptions inside 192.0.0.0/24 (PCP and TURN anycast).
    if ip == Ipv4Addr::new(192, 0, 0, 9) || ip == Ipv4Addr::new(192, 0, 0, 10) {
        return AddrClass::Global;
    }
    const BLOCKED: &[([u8; 4], u32, &str)] = &[
        ([0, 0, 0, 0], 8, "this network"),
        ([127, 0, 0, 0], 8, "loopback"),
        ([169, 254, 0, 0], 16, "link-local"),
        ([192, 0, 0, 0], 24, "IETF protocol assignments"),
        ([192, 0, 2, 0], 24, "documentation"),
        ([192, 88, 99, 0], 24, "deprecated 6to4 relay"),
        ([198, 18, 0, 0], 15, "benchmarking"),
        ([198, 51, 100, 0], 24, "documentation"),
        ([203, 0, 113, 0], 24, "documentation"),
        ([224, 0, 0, 0], 4, "multicast"),
        ([240, 0, 0, 0], 4, "reserved"),
    ];
    const PRIVATE: &[([u8; 4], u32)] = &[
        ([10, 0, 0, 0], 8),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([100, 64, 0, 0], 10),
    ];
    if let Some((_, _, why)) = BLOCKED.iter().find(|(net, bits, _)| in_v4(ip, *net, *bits)) {
        return AddrClass::Blocked(why);
    }
    if PRIVATE.iter().any(|(net, bits)| in_v4(ip, *net, *bits)) {
        return AddrClass::Private;
    }
    AddrClass::Global
}

fn in_v6(ip: Ipv6Addr, net: [u16; 8], bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(net)) & mask
}

/// The IPv4 address an IPv6 address carries, if it is one of the forms that
/// tunnel or translate to IPv4. Teredo carries two: server and client.
fn embedded_v4(ip: Ipv6Addr) -> Vec<Ipv4Addr> {
    let o = ip.octets();
    let v4 = |a: u8, b: u8, c: u8, d: u8| Ipv4Addr::new(a, b, c, d);
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return vec![mapped];
    }
    if in_v6(ip, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        return vec![v4(o[12], o[13], o[14], o[15])];
    }
    if in_v6(ip, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48) {
        // RFC 6052 /48: bits 48-63 and 72-87, around the zero u octet.
        return vec![v4(o[6], o[7], o[9], o[10])];
    }
    if in_v6(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        return vec![v4(o[2], o[3], o[4], o[5])];
    }
    if in_v6(ip, [0x2001, 0, 0, 0, 0, 0, 0, 0], 32) {
        // Teredo: the server in clear, the client's address inverted.
        let server = v4(o[4], o[5], o[6], o[7]);
        let client = v4(!o[12], !o[13], !o[14], !o[15]);
        return vec![server, client];
    }
    Vec::new()
}

pub fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    let carried = embedded_v4(ip);
    if !carried.is_empty() {
        // The strictest of what it carries decides.
        let classes: Vec<_> = carried.into_iter().map(classify_v4).collect();
        return classes
            .iter()
            .find(|c| matches!(c, AddrClass::Blocked(_)))
            .or_else(|| classes.iter().find(|c| **c == AddrClass::Private))
            .copied()
            .unwrap_or(AddrClass::Global);
    }
    // Globally reachable exceptions inside 2001::/23.
    const GLOBAL_IN_2001: &[([u16; 8], u32)] = &[
        ([0x2001, 0x1, 0, 0, 0, 0, 0, 0x1], 128),
        ([0x2001, 0x1, 0, 0, 0, 0, 0, 0x2], 128),
        ([0x2001, 0x3, 0, 0, 0, 0, 0, 0], 32),
        ([0x2001, 0x4, 0x112, 0, 0, 0, 0, 0], 48),
        ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
        ([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
    ];
    if GLOBAL_IN_2001
        .iter()
        .any(|(net, bits)| in_v6(ip, *net, *bits))
    {
        return AddrClass::Global;
    }
    const BLOCKED: &[([u16; 8], u32, &str)] = &[
        ([0, 0, 0, 0, 0, 0, 0, 0], 128, "unspecified"),
        ([0, 0, 0, 0, 0, 0, 0, 1], 128, "loopback"),
        ([0, 0, 0, 0, 0, 0, 0, 0], 96, "deprecated IPv4-compatible"),
        ([0x100, 0, 0, 0, 0, 0, 0, 0], 64, "discard-only"),
        (
            [0x2001, 0, 0, 0, 0, 0, 0, 0],
            23,
            "IETF protocol assignments",
        ),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32, "documentation"),
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, "documentation"),
        ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16, "segment routing"),
        ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, "link-local"),
        ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, "deprecated site-local"),
        ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, "multicast"),
    ];
    if let Some((_, _, why)) = BLOCKED.iter().find(|(net, bits, _)| in_v6(ip, *net, *bits)) {
        return AddrClass::Blocked(why);
    }
    if in_v6(ip, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7) {
        return AddrClass::Private;
    }
    AddrClass::Global
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(s: &str) -> AddrClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn public_addresses_are_global() {
        for ip in [
            "1.1.1.1",
            "140.82.112.4",
            "192.0.0.9",
            "2606:4700::1111",
            "2001:4:112::1",
        ] {
            assert_eq!(class(ip), AddrClass::Global, "{ip}");
        }
    }

    #[test]
    fn private_ranges_need_the_opt_in() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "100.64.0.1",
            "fd00::1",
        ] {
            assert_eq!(class(ip), AddrClass::Private, "{ip}");
        }
        assert_eq!(class("172.32.0.1"), AddrClass::Global);
    }

    #[test]
    fn special_purpose_addresses_are_blocked() {
        for ip in [
            "0.0.0.0",
            "127.0.0.1",
            "127.8.9.10",
            "169.254.169.254",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::1.2.3.4",
            "100::1",
        ] {
            assert!(matches!(class(ip), AddrClass::Blocked(_)), "{ip}");
        }
    }

    #[test]
    fn ipv6_forms_carrying_ipv4_are_judged_by_it() {
        // Mapped, NAT64 /96 and /48, 6to4.
        assert!(matches!(class("::ffff:127.0.0.1"), AddrClass::Blocked(_)));
        assert!(matches!(class("64:ff9b::a9fe:a9fe"), AddrClass::Blocked(_)));
        assert!(matches!(
            class("64:ff9b:1:7f00:0:100::"),
            AddrClass::Blocked(_)
        ));
        assert!(matches!(class("2002:7f00:1::"), AddrClass::Blocked(_)));
        assert_eq!(class("2002:c0a8:101::"), AddrClass::Private);
        assert_eq!(class("::ffff:1.1.1.1"), AddrClass::Global);
        // Teredo whose client is 127.0.0.1 (inverted: 80ff:fffe).
        assert!(matches!(
            class("2001:0:4136:e378:8000:63bf:80ff:fffe"),
            AddrClass::Blocked(_)
        ));
    }
}
