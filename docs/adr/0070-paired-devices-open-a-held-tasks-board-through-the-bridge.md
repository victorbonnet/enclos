---
status: proposed
---

# Paired devices open a held task's board through the bridge

A task held for a decision on its runtime's board can show up on a phone whose only route to the host is the bridge. A separate board address adds a step to setup, and publishing the full runtime dashboard would expose more of the sandbox than the decision needs.

Amends [0066](0066-held-tasks-stay-with-the-runtime.md) by offering browser access for a current held task to the host's person on a paired device. The bridge serves the task's board through its existing HTTPS address and starts the private runtime dashboard under the agent's sandbox policy. A one-minute, single-use launch ticket reaches the browser in the fragment. The bridge binds the 15-minute browser session to the device's transport node, pairing and host person, and authorizes each request.

For Hermes the relay allows reads of the selected board, and uses Hermes's task update (`PATCH`), comment and specify operations only on the selected task. Before forwarding a write, the bridge checks that it still has the exact held card and audits the request with the device and person. Hermes applies its own rules to the write. The CLI dashboard keeps its local routes from [0040](0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md) and [0063](0063-a-dashboard-on-macos-uses-a-private-inherited-socket.md). The CLI and bridge use separate locks on Bubblewrap. On macOS they share the sandbox's dashboard lock.

## Consequences

- The bridge's HTTPS origin now serves Hermes's page, scripts and assets from inside the sandbox that controls them. The page can run same-origin and inline scripts. Those scripts can make same-origin requests to which `tailscale serve` attaches the caller's transport identity. A future HTTP endpoint on this origin will be reachable from sandbox-supplied scripts and needs its own authorization beyond transport identity.
- The bridge's pairing page is static and receives its pairing code in the URL fragment. A board exchange requires a single-use ticket, other boards require their own browser session, and the device WebSocket requires the device's Noise keys or a one-time pairing code. The relay refuses workers and WebSocket upgrades.

## Considered options

- **Use a separate HTTPS origin for the board.** A different `tailscale serve` port would isolate the bridge origin from Hermes's scripts. It would add a served address and require the app to discover it. The shared origin lets a paired phone use the address it already knows.
