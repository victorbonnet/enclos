---
status: accepted
---

# Secrets reach a sandbox only as environment variables, through `enclos launch`

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine. A profile's service unit always runs `enclos launch <sandbox>/<profile>`, which runs outside the sandbox, reads the secrets the policy grants, and starts the agent with them as environment variables. Secrets are never written to a plist, a unit file or the sandbox home.

## Consequences

- While secrets are granted per sandbox (per-profile grants are still an open decision in the design), every profile in a sandbox can read them.
- With v1 subscription logins, the agent's own refresh token stays in the sandbox home, readable by the agent. enclos flags this; a host-side refresh owner that hands out short-lived tokens is planned.
