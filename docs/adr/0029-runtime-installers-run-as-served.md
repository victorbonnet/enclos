---
status: proposed
---

# A runtime's installer runs as the runtime serves it, not pinned by hash

[ADR 0020](0020-runtimes-installed-per-sandbox.md) had enclos run a runtime's installer only if its SHA-256 was the one reviewed, and refuse a changed one until enclos was updated. Hermes changes its installer often (at least eight commits to `scripts/install.sh` in the week to 2026-10-21, the last a fix for damaged checkouts), and each change stopped every `enclos runtime install` until a new enclos was released, for a script that installs whatever Hermes version the stable channel serves anyway.

enclos now downloads the installer the runtime serves at install time, over HTTPS only and within the size limit as before, and runs it whatever its content. The `runtime install` audit entry names its SHA-256, so what ran can be traced.

The pin's protection was weak where it mattered: the installer runs inside the sandbox, under its compiled policy and through its proxy, so a changed or hostile installer can reach only the sandbox's home and the destinations its policy allows, as the runtime it installs can ([0014](0014-threat-model-accidental-damage.md)). Following the runtime's own releases is what enclos aims for: it adapts to the runtime, never the reverse.

## Consequences

- A change to the installer is not reviewed before it runs. Whoever controls the installer's URL (`hermes-agent.nousresearch.com`) controls what runs in a sandbox during an install, as they already control the Hermes code it installs.
- Two sandboxes installed at different times can have run different installers; their audit entries say which.
