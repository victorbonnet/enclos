---
status: proposed
---

# A runtime declares how its own service listener is selected

Amends only [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md)'s ephemeral-port selection. Hermes binds port 0, so selecting its one ephemeral loopback listener excludes fixed auxiliary listeners. OpenClaw's gateway rejects port 0 and uses a configured positive port ([2026.11.2 source](https://github.com/openclaw/openclaw/blob/v2026.11.2/src/cli/gateway-cli/run.ts)). Assuming every runtime binds port 0 prevents its clients from reaching it.

Decision (proposed): `RuntimeListener` declares `ListenerPorts::Ephemeral` or `SingleLoopback`. Hermes keeps the former. The latter selects exactly one positive TCP port at **127.0.0.1** from the recorded service root process, regardless of the host's ephemeral range. It is a candidate-selection contract, not a grant to all loopback ports. The engine still requires one live service session, the same root process before and after reading sockets, no other process holding the selected loopback port, and, for a host-network listener, a port outside enclos's proxy range. Shared-namespace listeners retain the existing process/network-namespace corroboration and ownership checks. Zero candidates waits for startup; several candidates, shared ownership or a protected proxy port are refused. A sandbox-written port file is never proof of ownership.

Reason: runtimes vary in how they choose a port; process ownership is the evidence that it is their service. A runtime with more than one eligible root-process listener needs a narrower future declaration instead of a guess. There is no new member-process ownership rule, IPv6/wildcard grant, native readiness claim or dashboard authentication change. Existing policy behavior and ADR 0028's lifetime/reused-port limitations remain.

The selector and test-owned listener cases are implemented in M5-05. OpenClaw worker ownership, authenticated readiness, external restart handoff and native hot reload remain to probe; this amendment does not establish that OpenClaw runs under enclos or works on Linux.
