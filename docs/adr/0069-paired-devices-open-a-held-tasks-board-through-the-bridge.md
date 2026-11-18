---
status: proposed
---

# Paired devices open a held task's board through the bridge

A task held for a decision on its runtime's board can show up on a phone whose only route to the host is the bridge. A board URL copied to that phone is another address to configure, and publishing the runtime dashboard would open more of the sandbox than the decision needs.

Amends [0066](0066-held-tasks-stay-with-the-runtime.md) by offering browser access for a current held task to the host's person on a paired device. The existing private dashboard session machinery opens the runtime in its sandbox. The bridge serves the task's board through its existing HTTPS address. The launch ticket is single use, expires, and reaches the browser in the fragment. The bridge binds the browser session to the device's transport node, pairing and host person, and authorizes each request. On Hermes the relay admits board reads and changes to the selected task. The runtime's board runs the decision under its own rules.

The dashboard keeps its private upstream socket. A short browser session and narrow request routing let a paired phone use the same transport address it already knows. The CLI dashboard remains available by the local routes in [0040](0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md) and [0063](0063-a-dashboard-on-macos-uses-a-private-inherited-socket.md). On macOS the phone and CLI share the sandbox's dashboard lock.
