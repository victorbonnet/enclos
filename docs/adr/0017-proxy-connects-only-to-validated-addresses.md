---
status: accepted
---

# The proxy connects only to addresses it has validated

Checking the syntax of allowlist entries is not enough: an allowed hostname can resolve, or later re-resolve, to a loopback, link-local or private address. So the proxy resolves every hostname itself (the sandbox has no DNS of its own), checks every resolved IPv4 and IPv6 address against the blocked ranges, and connects only to addresses that passed, by address, never by handing the hostname to a client that would resolve it again. Retries and fallbacks between addresses use the same validated list; a retry that resolves again validates again. If every address is blocked, the request is denied and logged with the reason.

Blocked ranges include loopback, unspecified, link-local (including cloud metadata addresses), private and carrier-grade NAT ranges, unique-local IPv6, multicast and reserved ranges, and IPv6 forms that embed an IPv4 address (IPv4-mapped, NAT64, 6to4), which are checked as the IPv4 they carry. Private addresses are reachable only through an explicit opt-in for a named host, and the opt-in applies the same way whether the host is an IP literal or a hostname that resolves to a private address.

## Consequences

- A DNS answer that changes between check and connect (DNS rebinding) cannot reach a blocked address.
- Each network log record includes the address actually connected to.
- Local services on the host are unreachable by design. Access to one needs the host-service forwarding mechanism, which is still an open decision, not a loopback exception.
