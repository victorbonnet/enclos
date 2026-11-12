---
status: proposed
---

# A bridge on each host serves the mobile app

Amends [0002](0002-no-daemon.md): one service belongs to the install, not to a sandbox.

People want to talk to their agents from a phone, on every host, whatever the runtime, and to get a runtime's cron output in the conversation that asked for it, as a Telegram bot gives it today. The app is a **channel** like Telegram ([ADR 0036](0036-an-agent-has-its-own-bot.md)), reached over the user's own VPN (Tailscale). Something on the host has to listen for the phone; nothing in enclos does today, and no sandbox can reach the host ([0017](0017-proxy-connects-only-to-validated-addresses.md)).

Decision (proposed):

- **One bridge per install**, `enclos.<install>.bridge`, a service of the host's service manager like the sandboxes' own, using the core library. It listens on the host's loopback only, and reaches the person's network through a **transport**, chosen with `--transport`: Tailscale, through `tailscale serve`, is the only one for now, and says who each caller is. Another transport is one more case of that choice, not a change to the bridge. Each host's bridge serves that host's sandboxes; the phone gathers hosts, and no host manages another (§2).
- **The bridge dials in.** A runtime's channel plugin, which enclos's binary carries and writes into the sandbox home (Hermes: a gateway platform plugin; OpenClaw: a channel plugin), listens on a Unix socket in the sandbox home, one per agent. The sandbox gets no new way out, and no TCP listener the host's network reaches ([0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md), [0040](0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md)). The plugin accepts only a peer that presents the agent's token, a secret granted to that agent ([0036](0036-an-agent-has-its-own-bot.md)); the agent can read it too, so it keeps the host's other programs out, and no message from the bridge to the plugin carries authority the agent must not have.
- **The protocol is enclos's** (`docs/protocol.md`): conversations, people and capabilities, never a runtime's own words. A runtime that cannot send on its own (Claude Code, Codex) is reached through `enclos exec`, request and reply only.
- **Only paired devices.** A device pairs once per host by scanning a QR code that `enclos app pair` prints, and the user confirms it at the terminal. Its key stays in the phone's hardware. Every connection is a Noise handshake with the keys from pairing, and the bridge also checks with Tailscale that the caller is the device's own person and node. Pairing, unpairing and sharing are audit entries; connections and refusals go in the bridge's own log, as connections go in the network log.
- **Push without the content.** The bridge sends notifications through FCM, from the host, with the preview encrypted for the device; the phone fetches the message over the tailnet.

Reason: one listener per host is the least that reaches the phone, and dialing in keeps the sandbox's routes as they are. Every runtime then needs only its own plugin, and the app works with every agent.

## Considered options

- **The runtime's own apps** (OpenClaw ships Android and iOS ones): no enclos code, but one app per runtime, the runtime's whole control plane on the tailnet, and the phone offered to the agent as a device (camera, location, SMS) outside the sandbox's policy.
- **A Matrix homeserver on the tailnet**, each agent a Matrix bot: no app to write, but another server to run, and push through a third party that sees metadata.
- **The gateway's own listener, forwarded**: per-runtime and per-port, and on Linux not reachable from the host at all (0040).

## Consequences

- The threat model ([0014](0014-threat-model-accidental-damage.md)) gains actors: someone other than the user trying to reach the agents (another device of the tailnet, a stolen phone, another program of the host), and, with sharing ([0043](0043-sharing-an-agent-is-not-hosting-it.md)), people the user trusts in part.
- Chat history the bridge keeps sits on the host, outside every sandbox; it needs a retention setting.
- The phone may read enclos's state (who has access, which devices are connected) but changes nothing in it: changing a sandbox from a phone stays a non-goal (§2).
- That a gateway can bind a socket in the sandbox home and the host can connect to it was shown on a Mac (`prototype/m4/README.md`); on Linux it is to verify (§14).
