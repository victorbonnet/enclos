# Network: domain allow-list through a proxy, enforced by isolation

The sandboxed command can only reach a proxy that enclos runs outside the sandbox, and the proxy allows only the domains in the policy. On Linux the command runs in its own network namespace, whose only way out is the proxy. On macOS the Seatbelt profile allows connections to the proxy's localhost port and nothing else.

## Considered options

- **Landlock port rules instead of a namespace:** Landlock can restrict TCP connections by port but not by address, so any host on the proxy's port number would be reachable.
- **Network fully on or off:** simplest, but an agent that needs its own API would also get the whole internet.

## Consequences

- On Linux, creating the network namespace needs an unprivileged user namespace. On Ubuntu 24.04+ this requires an AppArmor profile for the enclos binary, which enclos must ship and document.
- Only traffic that goes through the proxy works. Tools that ignore proxy settings will fail to connect, which is the safe failure.
