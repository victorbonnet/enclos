---
status: proposed
---

# A runtime declares how its own service listener is selected

Amends only [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md)'s ephemeral-port selection. Hermes binds port 0, so selecting its one ephemeral loopback listener excludes fixed auxiliary listeners. OpenClaw's gateway rejects port 0 and uses a configured positive port ([2026.11.2 source](https://github.com/openclaw/openclaw/blob/v2026.11.2/src/cli/gateway-cli/run.ts)). Assuming every runtime binds port 0 prevents its clients from reaching it.

Decision (proposed): `RuntimeListener` declares `ListenerPorts::Ephemeral`, `SingleLoopback` or `Loopback(port)`. Hermes keeps ephemeral selection. `SingleLoopback` selects exactly one positive TCP port at **127.0.0.1** from the recorded service root process, regardless of the host's ephemeral range. `Loopback(port)` selects only the exact positive IPv4 loopback endpoint declared by the adapter from the host-owned launch contract. OpenClaw derives that port from the sandbox's allocated proxy port plus 2000, exactly as its launcher does. Auxiliary sockets are not candidates for that declaration.

Selection does not grant access by itself. The engine still requires one live service session, the same root process before and after reading sockets, no other process holding the selected loopback port, and, for a host-network listener, a port outside enclos's proxy range. Shared-namespace listeners retain the existing process/network-namespace corroboration and ownership checks. Zero candidates waits for startup; ambiguous selection, shared ownership or a protected proxy port are refused. Neither a sandbox-written port file nor an adapter's declaration is proof that the recorded process owns the endpoint.

Reason: runtimes vary in how they choose a port; process ownership is the evidence that it is their service. OpenClaw 2026.11.3 opened auxiliary loopback listeners after fresh agent turns on Ubuntu, so counting every loopback socket incorrectly stopped recognizing its already configured Gateway port. An exact declaration avoids guessing among those sockets. There is no new member-process ownership rule, IPv6/wildcard grant, native readiness claim or dashboard authentication change. Existing policy behavior and ADR 0028's lifetime/reused-port limitations remain.

The initial selectors and test-owned listener cases were implemented in M5-05. Exact-port selection was added during the OpenClaw transfer probes, with auxiliary-listener, foreign-owner, shared-port and address checks. This selection contract alone does not establish model health, external restart handoff or native hot reload.
