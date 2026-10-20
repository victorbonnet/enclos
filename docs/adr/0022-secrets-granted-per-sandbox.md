---
status: accepted
---

# Secrets are granted per sandbox, as environment variables at session start

Supersedes [0011](0011-secrets-only-as-env-at-launch.md), which granted secrets per agent.

Decided; built in milestone 2: secret storage, grants and injection are not implemented yet, and a policy holds only filesystem and network rules today.

Secrets are stored in the macOS Keychain, libsecret, or a `0600` file on a headless machine, referenced as `secret:<sandbox>/<name>`. A sandbox's policy will grant secrets to the sandbox as a whole. Host-side session setup, which runs outside the sandbox, will read the secrets the session's policy snapshot grants and start the session with them as environment variables: every session, whichever agent it runs (an interactive `connect`, an `exec` once it exists), and the runtime services started through `enclos launch <sandbox> <service>` alike. enclos will never write secret values to a plist, a unit file or the sandbox home; once a runtime has a value in its environment, it may save or log it in its own home, which enclos cannot prevent. The sandbox has no Keychain access of its own: Seatbelt denies the security daemons and the keychain files, part of the host-service blocks in [0016](0016-seatbelt-blocks-host-service-delegation.md), and the `keychain` probe of `policy test` shows that reading the login keychain's settings is refused. That no keychain item can be read from inside is still to verify.

Per-agent grants would not provide isolation. The sandbox is the permission boundary and its agents share a home ([0003](0003-sandbox-is-the-permission-boundary.md)), so any agent can read what another saved. One gateway serves every agent of a sandbox ([0021](0021-one-runtime-service-per-sandbox.md)), so it would need every agent's secrets anyway, and messaging, the first use of secrets, runs in that gateway. Agents also already share the runtime's login: in the prototype, agents with no login of their own used the sandbox's.

## Consequences

- Two agents that must not share a secret go in different sandboxes.
- A secret is fixed when a session starts, as environment variables are: changing a grant or rotating a value takes a restart of the sessions and services that use it.
- Every agent of a sandbox can use every secret granted to it. If a runtime needs to know which secret belongs to which agent, such as one Telegram bot token per agent, that is routing in its adapter, not a boundary; whether Hermes's gateway can take per-agent tokens from environment variables is to verify in milestone 2.
- Subscription logins are different: the first one is Hermes with an existing ChatGPT subscription, through Hermes's own supported login flow, run inside the sandbox as a device-code login (the user opens a URL and enters a code on the host). enclos makes no network exception for logins and does not copy in tokens from a host login. The runtime's refresh token stays in the sandbox home, readable by every agent there. enclos will flag this; a host-side refresh owner that hands out short-lived tokens is planned (design §12).
