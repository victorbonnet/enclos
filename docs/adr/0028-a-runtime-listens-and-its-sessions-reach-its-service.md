---
status: proposed
---

# A runtime may listen in its sandbox, and the sandbox's sessions reach its service's port

Hermes 0.22.3's gateway binds a TCP listener on `127.0.0.1:0` when it starts, for its session WebSocket (`/api/ws`) and its dashboard, and exits if the bind is refused. Its chat (CLI, TUI, stream-json) never runs on its own: it finds the gateway, gets a ticket for its profile over the gateway's Unix socket in the home, and dials the address the gateway gives, starting a gateway if none runs; it fails with no fallback when it cannot. The compiled policy's `(deny network*)` refuses both the bind and the dial, so neither the gateway nor any chat works in a sandbox (issue #64). enclos adapts to the runtime as it ships, so it changes, not Hermes.

Opening outbound loopback (`localhost:*`) would let the chat dial its gateway, and also every other loopback service: other sandboxes' proxies, and with them their policies, other sandboxes' gateways, and the user's own tools. That is the loopback exception §6 rules out.

So, for a runtime whose adapter declares it:

- **It may listen.** The compiled policy allows `network-bind` and `network-inbound` on TCP, and denies binding every port of enclos's proxy range, 41000 to 41999, by exact port: whichever install reserved it, before or after the session started, so no sandbox can take another's proxy port while that proxy is not running and receive what that sandbox's sessions send it.
- **Its sessions reach its service's port.** The adapter names the service that listens (Hermes: `gateway`). When a session starts and that service listens, the session's compiled policy also allows outbound TCP to that one port on loopback, besides the proxy port. enclos takes the port from its records of the service's session: the one TCP port the program it started for the service holds, checked to be the same process before and after, and none when that program holds no port or several. Hermes then works as it does outside enclos: each client finds the gateway, gets a ticket for its own profile, and dials the gateway, so every agent, the CLI and the TUI each reach it as themselves.
- **`connect` starts the service** when the runtime is installed and no session of the service is open, waits for it to listen, and says so: a session started before the service listens cannot reach it.

Seatbelt cannot hold a listener to loopback: `(local tcp "localhost:*")` also allows a bind on `0.0.0.0`, which the host's network reaches, and no inbound filter on the peer's address changed that (macOS 26.5.2). So anything in such a sandbox can serve the network on a port that is not a proxy port. Under the threat model ([0014](0014-threat-model-accidental-damage.md)), a misled agent is unlikely to do that and a compromised one could; `enclos status` names such listeners, and `enclos policy test` reports listening as open, not closed.

This revises the "no port" of [0024](0024-agents-reached-through-the-runtime.md) for a runtime that declares a listener: agents still have no port of their own, and the sandbox still has one proxy port for its way out, but its sessions also reach the port of its own service.

## Considered options

- **Outbound loopback for the sandbox:** works with nothing else, and opens every service on the host's loopback, other sandboxes' proxies among them (above).
- **A forward through the proxy, with the address and a token in the environment** (`HERMES_TUI_GATEWAY_URL`, `HERMES_DASHBOARD_SESSION_TOKEN`): survives a gateway restart, but Hermes binds a session reached that way to the gateway's launch profile, and no client can name another, so every named agent ran as `default`; Hermes's kanban refuses that address outright. Making it pick the profile would mean minting tickets over Hermes's private control protocol, from a profile enclos would have to guess.
- **One more reserved port per sandbox for the runtime's listener:** Seatbelt can allow exactly one port, but Hermes binds port 0 and has no setting for its port.
- **Pinning an older Hermes, or asking Hermes for a Unix-socket listener:** each makes enclos depend on the runtime not moving.
- **Denying only the proxy ports reserved when the policy is compiled:** a few rules, but a sandbox started before another was created can bind the newer one's port once that proxy exits, and the newer sandbox's running sessions then send their connections to it. Seatbelt has no port ranges, so the range is denied port by port: 1,000 rules add about 0.03 s to a launch (macOS 26.5.2), where the earlier range of 8,000 added 0.9 s, so the range is now 1,000 ports.

## Consequences

- A session reaches the port the service held when the session started. When the service restarts, it binds another port, and the sessions opened before cannot reach it until they are opened again; the port they may reach stays allowed for their lifetime, so another program that later listens on it, on the host or in another sandbox, would be reachable from them.
- The service itself, and what it starts, were compiled before it listened, so they cannot reach it on that port: Hermes's kanban workers that the gateway starts cannot.
- A sandbox whose runtime declares a listener can be reached on that listener from the host, as the runtime is outside enclos: Hermes's dashboard works in the host's browser, and Hermes leaves its auth gate off on loopback.
- enclos's proxy ports are 41000 to 41999, every install's: at most 1,000 sandboxes on a Mac, fewer when other programs hold some of those ports. Programs outside enclos can still take one, as before (§4).
- Another runtime with a local service declares its service; one without declares nothing and keeps today's policy.
