---
status: proposed
---

# On Linux, a sandbox's service is reached from inside the sandbox

Amends [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md) for the bubblewrap backend.

0028 lets a runtime that declares a listening service listen in its sandbox. Its consequences say that the host can reach that listener: Hermes's dashboard works in the host's browser, and a listener bound to every address serves the host's network. On Linux every session, the service's included, has its own network namespace ([0004](0004-linux-bubblewrap-and-landlock.md), [0039](0039-a-bubblewrap-session-has-its-own-namespaces-and-its-services-port-is-relayed.md)). The M3-03 prototype showed, on GitHub's Ubuntu 24.04 runners, x86_64 and arm64, that the host cannot reach a listener in a session's namespace, on 127.0.0.1 or on every address (ECONNREFUSED) (`prototype/m3/README.md`).

Decision (proposed), on the bubblewrap backend:

- **The dashboard is reached from inside the sandbox**, until milestone 4.1's host-service forwards give a named, logged way in. A session given the service's port reaches it through its relay (0039).
- **`status` names the listener without a URL.** It gives the service and its port and says the port is reachable from the sandbox's sessions. It shows no `http://127.0.0.1:<port>/` that would not work from the host. On macOS it shows the dashboard as before.
- **Listening.** `policy show` and `policy test` say that the sandbox may listen, and that its listeners are reachable from its own sessions alone. No rule needs to keep the sandbox off enclos's proxy ports: those ports are on the host's loopback, which a session's own namespace does not share. `status` naming listeners beyond loopback stays as 0028 has it, since none of them serve the host's network on Linux.
- **0028's rule that a session reaches its sandbox's service port and no other is unchanged** on Linux: 0039 relays that one port.

Reason: the network namespace that keeps the sandbox off the host's loopback and network (0004) also keeps the host off the sandbox's listeners. Opening a way in is the host-service forward that milestone 4.1 plans: one named port per grant, logged and audited. Adding it here would open an unlogged path from the host into a sandbox before that design is settled. Stating the difference in `status` is better than showing a URL that fails.

## Consequences

- On Linux, Hermes's dashboard cannot be opened in the host's browser until milestone 4.1. A browser inside the sandbox, or a client in a `connect` session, reaches it.
- 0028's consequence that a listener bound to every address serves the host's network does not hold on Linux. Within the sandbox's sessions, listening stays open, as 0028 says.
- macOS behaves as 0028 says; this ADR changes nothing there.
