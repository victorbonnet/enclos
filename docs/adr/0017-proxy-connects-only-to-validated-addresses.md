---
status: accepted
---

# The proxy connects only to addresses it has validated

Checking the syntax of allowlist entries is not enough: an allowed hostname can resolve, or later re-resolve, to a loopback, link-local or private address. So the proxy resolves every hostname itself (the sandbox is denied DNS of its own, see [0016](0016-seatbelt-blocks-host-service-delegation.md)), checks every resolved IPv4 and IPv6 address against the blocked ranges, and connects only to addresses that passed, by address, never by handing the hostname to a client that would resolve it again. Retries and fallbacks between addresses use the same validated list; a retry that resolves again validates again. If every address is blocked, the request is denied and logged with the reason.

Always blocked: every entry of the IANA IPv4 and IPv6 special-purpose address registries that is not globally reachable (loopback, unspecified, link-local and with it cloud metadata addresses, multicast, benchmarking, documentation and similar), and IPv6 forms that embed an IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo), which are checked as the IPv4 they carry. Private ranges (RFC 1918, carrier-grade NAT, unique-local IPv6) are reachable only for a host that is on the allowlist and also named in the policy's `private` opt-in; the opt-in never unlocks loopback, link-local or multicast, and applies the same way whether the host is an IP literal or a hostname that resolves to a private address.

## Consequences

- A DNS answer that changes between check and connect (DNS rebinding) cannot reach a blocked address.
- Each network log record includes the address actually connected to.
- Local services on the host are unreachable by design. Access to one will come in milestone 3.1 through a host-service forward that exposes one named host port to one sandbox, never a loopback exception.
