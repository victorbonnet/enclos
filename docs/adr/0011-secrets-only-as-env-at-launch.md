---
status: accepted
---

# Secrets reach a sandbox only as environment variables, through `enclos launch`

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine. Every session starts through `enclos launch` (an agent's service unit runs `enclos launch <sandbox>/<agent>`; `connect` and `exec` call it too), which runs outside the sandbox, reads the secrets the policy grants to that agent, and starts the agent with them as environment variables. Secrets are never written to a plist, a unit file or the sandbox home. The sandbox itself is meant to have no Keychain access; that is part of the host-service blocks in [0016](0016-seatbelt-blocks-host-service-delegation.md) and is still to verify.

## Consequences

- Secrets are granted per agent: an agent's session receives only the variables granted to it. Agents share a home, so this guards against mistakes, not against one agent reading what another saved to disk ([0003](0003-sandbox-is-the-permission-boundary.md)).
- Subscription logins are different: the first one is Hermes with an existing ChatGPT subscription, through Hermes's own supported login flow, run inside the sandbox as a device-code login (the user opens a URL and enters a code on the host). enclos makes no network exception for logins and does not copy in tokens from a host login. The runtime's refresh token stays in the sandbox home, readable by every agent there. enclos flags this; a host-side refresh owner that hands out short-lived tokens is planned.
