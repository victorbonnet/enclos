---
status: accepted
---

# Network: one egress proxy per sandbox, enforced by enclos

Each sandbox reaches the outside only through its own egress proxy, a domain-level CONNECT proxy without TLS interception that applies the policy's domain allowlist and logs every request. Backends only have to make the proxy the sole way out: on macOS the compiled Seatbelt policy allows outbound connections to the proxy's localhost port only, and on Linux the sandbox runs in an empty network namespace whose only way out is a Unix socket to the proxy. Network rules are therefore the same on every backend and can change without a restart.

## Consequences

- The proxy sees domains, not request contents. Exfiltration through an allowed domain is possible and is addressed by a narrow allowlist and the network log.
- Requests to unknown domains can be held for a decision (allow once, always, or deny), so a policy for a new agent can be built without guessing its endpoints.
- Programs that ignore `HTTPS_PROXY` cannot connect, which is the safe failure.
- Most HTTP clients (Python `httpx` and `requests`, Node, Go) need a TCP address in `HTTPS_PROXY`, but the Linux sandbox only has a Unix socket. So `wrap` also starts a small relay inside the sandbox (enclos itself) that listens on `127.0.0.1:<port>` and forwards to the socket, one per profile, which keeps the network log per profile. The relay is the enclos binary, so the bubblewrap sandbox always mounts it and the program allowlist always permits it, even with `shell = false`. The agent can kill or replace its relay; that is harmless, because the relay can only reach the proxy socket and per-profile attribution is informative.
