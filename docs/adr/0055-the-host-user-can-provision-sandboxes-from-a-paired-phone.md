---
status: proposed
---

# The host's user can provision sandboxes from a paired phone

Amends [0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md)'s original read-only sandbox boundary, alongside policy management in [0047](0047-the-hosts-person-manages-sandbox-policy-from-the-phone.md). The host's user wants to create a sandbox and install its runtime while using the mobile app, including on a host that has no agents yet. The bridge therefore offers these two changes to paired devices whose authenticated transport login equals the host's own transport login, read from Tailscale or explicitly set with `app serve --owner`. If ownership cannot be determined, these operations are unavailable; pairing alone never establishes ownership.

Creation uses an explicitly selected built-in policy template and the host's configured default backend. Installation uses the runtime's existing engine and audit behavior, in a separate enclos process with no terminal input, so a long install does not occupy the device connection or take the bridge's terminal. An install refuses unrelated policy edits that need confirmation, as the CLI does without `--yes`. The bridge logs the requesting device and person; the engine audit records sandbox creation by that person and installation by the host user executing its CLI process. Login, app channel configuration, service startup and removal remain host operations. Existing policy management from the phone remains available. This keeps one small provisioning surface while preserving the sandbox's existing policy and lifecycle boundaries.
