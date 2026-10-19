---
status: accepted
---

# Secrets are granted per sandbox, as environment variables through `enclos launch`

Supersedes [0011](0011-secrets-only-as-env-at-launch.md), which granted secrets per agent.

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine, referenced as `secret:<sandbox>/<name>`. A sandbox's policy grants secrets to the sandbox as a whole. Every session starts through `enclos launch`, which runs outside the sandbox, reads the sandbox's secrets, and starts the session with them as environment variables: an interactive `connect` to any agent, an `exec`, and the runtime's gateway alike. Secrets are never written to a plist, a unit file or the sandbox home. The sandbox itself is meant to have no Keychain access; that is part of the host-service blocks in [0016](0016-seatbelt-blocks-host-service-delegation.md) and is still to verify.

Per-agent grants would protect nothing. The sandbox is the permission boundary and its agents share a home ([0003](0003-sandbox-is-the-permission-boundary.md)), so any agent can read what another saved. One gateway serves every agent of a sandbox ([0021](0021-one-runtime-service-per-sandbox.md)), so it would need every agent's secrets anyway, and messaging, the first use of secrets, runs in that gateway. Agents also already share the runtime's login.

## Consequences

- Two agents that must not share a secret go in different sandboxes.
- Every agent of a sandbox can use every secret granted to it. If a runtime needs to know which secret belongs to which agent, such as one Telegram bot token per agent, that is routing in its adapter, not a boundary; whether Hermes's gateway can take per-agent tokens from environment variables is to verify in milestone 2.
- Subscription logins are different: the first one is Hermes with an existing ChatGPT subscription, through Hermes's own supported login flow, run inside the sandbox as a device-code login (the user opens a URL and enters a code on the host). enclos makes no network exception for logins and does not copy in tokens from a host login. The runtime's refresh token stays in the sandbox home, readable by every agent there. enclos flags this; a host-side refresh owner that hands out short-lived tokens is planned.
