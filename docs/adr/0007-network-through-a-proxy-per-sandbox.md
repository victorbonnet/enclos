# Network: one egress proxy per sandbox, enforced by enclos

Each sandbox reaches the outside only through its own egress proxy, a domain-level CONNECT proxy without TLS interception that applies the policy's domain allowlist and logs every request. Backends only have to make the proxy the sole way out: on macOS the compiled Seatbelt policy allows outbound connections to the proxy's localhost port only, and on Linux the sandbox runs in an empty network namespace whose only way out is a Unix socket to the proxy. Network rules are therefore the same on every backend and can change without a restart.

## Consequences

- The proxy sees domains, not request contents. Exfiltration through an allowed domain is possible and is addressed by a narrow allowlist and the network log.
- Requests to unknown domains can be held for a decision (allow once, always, or deny), so a policy for a new agent can be built without guessing its endpoints.
- Programs that ignore `HTTPS_PROXY` cannot connect, which is the safe failure.
