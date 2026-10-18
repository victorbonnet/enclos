---
status: accepted
---

# Secrets reach a sandbox only as environment variables, through `enclos launch`

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine. Every session starts through `enclos launch` (a profile's service unit runs `enclos launch <sandbox>/<profile>`; `connect` and `exec` call it too), which runs outside the sandbox, reads the secrets the policy grants, and starts the agent with them as environment variables. Secrets are never written to a plist, a unit file or the sandbox home. The sandbox itself is meant to have no Keychain access; that is part of the host-service blocks in [0016](0016-seatbelt-blocks-host-service-delegation.md) and is still to verify.

## Consequences

- While secrets are granted per sandbox (per-profile grants are still an open decision in the design), every profile in a sandbox can read them.
- Subscription logins are different: the first one is Hermes with an existing ChatGPT subscription, through Hermes's own supported login flow, run inside the sandbox. The agent's refresh token stays in the sandbox home, readable by the agent. enclos flags this; a host-side refresh owner that hands out short-lived tokens is planned.
