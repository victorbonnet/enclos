//! Which addresses the proxy may connect to (ADR 0017).
//!
//! Every IANA IPv4 and IPv6 special-purpose block that is not globally
//! reachable is refused, except two kinds. The private ranges (RFC 1918,
//! carrier-grade NAT, unique-local `fc00::/7`) are unlocked for named hosts by
//! a policy's `private` opt-in. IPv6 forms that carry an IPv4 address at a
//! fixed place (mapped, the well-known NAT64 prefix, 6to4, Teredo) are judged
//! by that address. The local-use NAT64 prefix is refused whole, since where
//! it carries the IPv4 address depends on the operator.
//!
//! Any other IPv6 address outside `2000::/3`, the only block IANA allocates
//! for global unicast, is refused too. That covers a block reserved later
//! outside `2000::/3`; a block reserved later inside it is taken as global
//! until it is added to the table here.

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
    // Only the three entries inside `2000::/3` (`2001::/23`, `2001:db8::/32`,
    // `3fff::/20`) decide anything: the others would be refused by the
    // `2000::/3` check below anyway, and are listed so the reason names the
    // block.
    const BLOCKED: &[([u16; 8], u32, &str)] = &[
        ([0, 0, 0, 0, 0, 0, 0, 0], 128, "unspecified"),
        ([0, 0, 0, 0, 0, 0, 0, 1], 128, "loopback"),
        ([0, 0, 0, 0, 0, 0, 0, 0], 96, "deprecated IPv4-compatible"),
        // RFC 8215 lets an operator use an RFC 6052 prefix of /48, /56, /64
        // or /96 inside this /48, so the IPv4 address it carries cannot be
        // located.
        ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48, "local-use NAT64"),
        ([0x100, 0, 0, 0, 0, 0, 0, 0], 64, "discard-only"),
        ([0x100, 0, 0, 1, 0, 0, 0, 0], 64, "dummy prefix"),
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
    if !in_v6(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        // IANA's IPv6 address space registry marks these "Reserved by IETF".
        return AddrClass::Blocked("reserved IPv6");
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
            "2001:4860:4860::8888",
            "2a00:1450:4001::1",
            "2620:4f:8000::1",
            "2001:4:112::1",
            "2001:1::1",
            "2001:3::1",
            "2001:20::1",
            "2001:30::1",
            "64:ff9b::101:101",
            "::ffff:1.1.1.1",
            // Both ends of 2000::/3.
            "2000::",
            "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
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
        // Mapped, the well-known NAT64 prefix, 6to4.
        assert!(matches!(class("::ffff:127.0.0.1"), AddrClass::Blocked(_)));
        assert!(matches!(class("64:ff9b::a9fe:a9fe"), AddrClass::Blocked(_)));
        assert!(matches!(class("2002:7f00:1::"), AddrClass::Blocked(_)));
        assert_eq!(class("2002:c0a8:101::"), AddrClass::Private);
        assert_eq!(class("::ffff:1.1.1.1"), AddrClass::Global);
        // Teredo whose client is 127.0.0.1 (inverted: 80ff:fffe).
        assert!(matches!(
            class("2001:0:4136:e378:8000:63bf:80ff:fffe"),
            AddrClass::Blocked(_)
        ));
    }

    #[test]
    fn the_local_use_nat64_prefix_is_blocked_whatever_it_carries() {
        // Operators may use a /48, /56, /64 or /96 prefix inside
        // 64:ff9b:1::/48, so where the IPv4 address sits is unknown: the
        // whole block is refused, including addresses that a /48 layout
        // reads as public.
        for ip in [
            "64:ff9b:1::",
            "64:ff9b:1::1",
            "64:ff9b:1:101:1:100::",
            "64:ff9b:1:808:8:808:a9fe:a9fe",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(class(ip), AddrClass::Blocked("local-use NAT64"), "{ip}");
        }
    }

    #[test]
    fn the_dummy_prefix_is_blocked() {
        for ip in [
            "100:0:0:1::",
            "100:0:0:1::1",
            "100:0:0:1:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(class(ip), AddrClass::Blocked("dummy prefix"), "{ip}");
        }
    }

    #[test]
    fn ipv6_outside_global_unicast_is_blocked() {
        for ip in [
            "1:2::3",
            "100:0:0:2::1",
            "1000::1",
            "4000::1",
            "c000::1",
            "fe00::1",
            "::1:0:0:1",
            "::ffff:0:1.1.1.1",
            // Next to the IPv4-carrying forms, read as 1.1.1.1 by a lax
            // decoder: past 64:ff9b::/96, below ::ffff:0:0/96.
            "64:ff9b::1:101:101",
            "64:ff9b:2::1",
            "::fffe:101:101",
            // Just below 2000::/3.
            "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(class(ip), AddrClass::Blocked("reserved IPv6"), "{ip}");
        }
    }
}
