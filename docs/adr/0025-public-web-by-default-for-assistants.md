---
status: accepted
---

# The assistant template reaches the public web by default

With an allowlist only, a personal agent could not do what it is for: browse, research and call public APIs it finds on its own. Each new site was refused first, and the user had to name it before the agent could try again. The weather task in the first milestone shows it: the agent picks its own source, so no allowlist written in advance can name it.

So a policy's network has a mode. `public` lets the sandbox reach any public address on ports 80 and 443, as well as what the allowlist lists. `allowlist` lets it reach only what is listed. The built-in defaults are `allowlist`; the `assistant` template sets `public`. A sandbox that should reach only named destinations sets `mode = "allowlist"` in its `policy.toml`, and `enclos policy show` states the mode.

Both modes keep everything else the proxy does: every connection goes through the sandbox's proxy and is logged when the proxy decides on it ([0007](0007-network-through-a-proxy-per-sandbox.md) says when a record can be missing), the proxy resolves names itself, and it connects only to validated addresses ([0017](0017-proxy-connects-only-to-validated-addresses.md)). Loopback, link-local and metadata addresses are never reachable, and private ones only for a host on the allowlist and in the `private` opt-in. Other ports need an allowlist entry in either mode. Filesystem rules and host-service denials do not depend on the mode.

This supersedes, for the `public` mode, the immediate denial of every destination not on the allowlist in [0007](0007-network-through-a-proxy-per-sandbox.md), and the reliance on a narrow allowlist against exfiltration in [0014](0014-threat-model-accidental-damage.md).

## Consequences

- In `public` mode the network log is the record of where data went, not a limit on it: an agent can send what it reads to any public site. Sandboxes that hold data the user does not want to leave use `allowlist`.
- `enclos net denied` lists less in `public` mode: other ports, blocked and private addresses, and allowed names that failed to resolve are not denials (they are logged as allowed and failed).
- The runtime adapter's endpoints stay in the policy, so switching a sandbox to `allowlist` keeps the runtime working.
- A change of mode is a policy change like any other: a new snapshot, audited, applied to new connections at once.
