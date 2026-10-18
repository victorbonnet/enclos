# Secrets reach a sandbox only as environment variables, through `enclos launch`

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine. A profile's service unit always runs `enclos launch <sandbox>/<profile>`, which runs outside the sandbox, reads the secrets the policy grants, and starts the agent with them as environment variables. Secrets are never written to a plist, a unit file or the sandbox home.

## Consequences

- Every profile in a sandbox can read the secrets granted to that sandbox.
- With v1 subscription logins, the agent's own refresh token stays in the sandbox home, readable by the agent. enclos flags this; a host-side refresh owner that hands out short-lived tokens is planned.
