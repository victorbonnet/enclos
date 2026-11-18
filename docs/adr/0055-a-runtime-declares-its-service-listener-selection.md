---
status: proposed
---

# A runtime declares how its own service listener is selected

Amends only [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md)'s ephemeral-port selection. Hermes binds port 0, so selecting its one ephemeral loopback listener excludes fixed auxiliary listeners. OpenClaw's gateway rejects port 0 and uses a configured positive port ([2026.11.2 source](https://github.com/openclaw/openclaw/blob/v2026.11.2/src/cli/gateway-cli/run.ts)). Assuming every runtime binds port 0 prevents its clients from reaching it.

Decision (proposed): Hermes keeps the ephemeral-port selector. A runtime with a configured listener declares its exact TCP port on 127.0.0.1. The launcher and selector derive the port from the same sandbox allocation. The engine requires a live recorded service session, the same root process before and after reading its sockets, exclusive ownership of the selected loopback port and, on the host network, a port outside enclos's proxy range. Linux also corroborates the process's network namespace. The absence of that exact listening socket waits for startup. A sandbox-written port file is never proof of ownership.

Reason: the service may also hold auxiliary listeners of its own. The declared port identifies which one its clients need while retaining the process-ownership checks and the lifetime and port-reuse limitations of ADR 0028. A socket at any other address or port does not qualify.

Selector tests cover the recorded service and port matching. Authenticated readiness, external restart handoff and native hot reload remain to verify.
