---
status: proposed
---

# A runtime may listen in its sandbox, and its own clients reach its service through the sandbox's proxy

Hermes 0.22.3's gateway binds a TCP listener on `127.0.0.1:0` when it starts, for its session WebSocket (`/api/ws`) and its dashboard, and exits if the bind is refused. Its chat (CLI, TUI, stream-json) never runs on its own: it reaches a gateway over that WebSocket, starting one if none runs, and fails with no fallback when it cannot. The compiled policy's `(deny network*)` refuses both the bind and the dial, so neither the gateway nor any chat works in a sandbox (issue #64). enclos adapts to the runtime as it ships, so it changes, not Hermes.

Opening outbound loopback (`localhost:*`) would let the chat dial its gateway, and also every other loopback service: other sandboxes' proxies, and with them their policies, other sandboxes' gateways, and the user's own tools. That is the loopback exception §6 rules out.

So, for a runtime whose adapter declares it:

- **It may listen.** The compiled policy allows `network-bind` and `network-inbound` on TCP, and denies binding every port of enclos's proxy range, 41000 to 41999, by exact port: whichever install reserved it, before or after the session started, so no sandbox can take another's proxy port while that proxy is not running and receive what that sandbox's sessions send it. Outbound is unchanged: only the sandbox's own proxy port.
- **Its clients reach its service through the proxy.** The adapter names the service (Hermes: `gateway`), the path (`/api/ws`), and the variables that carry a token and the address. enclos keeps one token per sandbox, in the sandbox's folder outside its home, and passes it to the service and to every session. Sessions get the address `ws://127.0.0.1:<proxy port><path>?token=<token>` (Hermes: `HERMES_TUI_GATEWAY_URL`), and the service gets the token as the one it accepts (Hermes: `HERMES_DASHBOARD_SESSION_TOKEN`).
- **The proxy forwards only that.** A WebSocket upgrade to the declared path on the proxy's own address, with the sandbox's token, is forwarded to the service's listener. Anything else to that address is refused, as it is today. The proxy takes the listener from enclos's records of the service's session, never from a file the sandbox writes alone, and refuses when it cannot tell which listener is the service's. The token appears in no log.
- **`connect` starts the service** when the runtime is installed, declares a forward, and no session of that service is open, and says so, since the runtime's clients no longer start one themselves.

Seatbelt cannot hold a listener to loopback: `(local tcp "localhost:*")` also allows a bind on `0.0.0.0`, which the host's network reaches, and no inbound filter on the peer's address changed that (macOS 26.5.2). So anything in such a sandbox can serve the network on a port that is not a proxy port. Under the threat model ([0014](0014-threat-model-accidental-damage.md)), a misled agent is unlikely to do that and a compromised one could; `enclos status` names such listeners, and `enclos policy test` reports listening as open, not closed.

This revises the "no port" of [0024](0024-agents-reached-through-the-runtime.md) for a runtime that declares a listener: agents still have no port of their own, and the sandbox still has one proxy port, which now also carries the runtime's own clients to its service.

## Considered options

- **Outbound loopback for the sandbox:** works with no forward, and opens every service on the host's loopback, other sandboxes' proxies among them (above).
- **One more reserved port per sandbox for the runtime's listener:** Seatbelt can allow exactly one port, but Hermes binds port 0 and has no setting for its port.
- **Pinning an older Hermes, or asking Hermes for a Unix-socket listener:** each makes enclos depend on the runtime not moving.
- **Denying only the proxy ports reserved when the policy is compiled:** a few rules, but a sandbox started before another was created can bind the newer one's port once that proxy exits, and the newer sandbox's running sessions then send their connections to it. Seatbelt has no port ranges, so the range is denied port by port: 1,000 rules add about 0.03 s to a launch (macOS 26.5.2), where the earlier range of 8,000 added 0.9 s, so the range is now 1,000 ports.

## Consequences

- A sandbox whose runtime declares a listener can be reached on that listener from the host, as the runtime is outside enclos: Hermes's dashboard works in the host's browser, and Hermes leaves its auth gate off on loopback.
- enclos's proxy ports are 41000 to 41999, every install's: at most 1,000 sandboxes on a Mac, fewer when other programs hold some of those ports. Programs outside enclos can still take one, as before (§4).
- The forward follows the service across restarts, since it looks the listener up for each connection.
- Another runtime with a local service declares the same three things; one without declares nothing and keeps today's policy.
