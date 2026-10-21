---
status: accepted
---

# Network: one egress proxy per sandbox, enforced by enclos

Each sandbox reaches the outside only through its own egress proxy, a domain-level CONNECT proxy without TLS interception that applies the policy's domain allowlist and logs every connection it decides on. Backends only have to make the proxy the sole way out: on macOS the compiled Seatbelt policy allows outbound connections only to the sandbox's reserved proxy port on localhost ([0024](0024-agents-reached-through-the-runtime.md)), and on Linux the sandbox runs in an empty network namespace whose only way out is a Unix socket to the proxy. Network rules are therefore the same on every backend and can change without a restart. The proxy connects only to resolved addresses it has validated ([0017](0017-proxy-connects-only-to-validated-addresses.md)).

A connection to a destination not on the allowlist is denied at once and logged for the user to review later. The agent cannot widen its own policy: only the user, from the host, can allow a destination, and the proxy's control channel and enclos's state are out of the sandbox's reach.

## Considered options

- **Hold unknown requests and ask the user:** builds a policy quickly, but stalls an agent working on its own and invites approving requests without context. Reviewing denials afterwards and allowing what is needed covers the same need.

## Consequences

- For HTTPS the proxy sees one tunnel per connection: the host and port asked for, the address connected to, bytes and duration. It does not see the individual HTTP requests inside the encrypted tunnel, so the network log never claims to.
- For TLS tunnels, the proxy compares the server name in the unencrypted ClientHello with the host the tunnel was opened for and closes mismatches, without decrypting anything. A tunnel with no visible name (absent or encrypted) is allowed and logged as such.
- The proxy controls which destinations the sandbox connects to, not what those destinations do. A remote browser, search service, MCP server or the model provider's own tools can fetch other sites on the agent's behalf, so allowing such a service grants that capability, and the design describes it that way.
- Exfiltration through an allowed destination is possible and is addressed by a narrow allowlist and the network log.
- The log is complete only while the proxy can write it: a connection whose record cannot be written goes ahead, and the proxy reports the failure in its service log. [0027](0027-network-log-completeness-and-retention.md) (proposed) weighs refusing it instead.
- Programs that ignore `HTTPS_PROXY` cannot connect, which is the safe failure.
- Most HTTP clients (Python `httpx` and `requests`, Node, Go) need a TCP address in `HTTPS_PROXY`, but the Linux sandbox only has a Unix socket. So `wrap` also starts a small relay inside the sandbox (enclos itself) that listens on `127.0.0.1:<port>` and forwards to the socket, one per sandbox. The relay is the enclos binary, so the bubblewrap sandbox always mounts it and the program allowlist always permits it, even with `shell = false`. The agent can kill or replace its relay; that is harmless, because the relay can only reach the proxy socket.
