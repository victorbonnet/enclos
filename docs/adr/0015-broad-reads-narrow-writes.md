---
status: accepted
---

# Broad reads, narrow writes, and agent-managed installs in the sandbox home

By default a sandbox can read the host broadly, except a deny list of sensitive paths (credentials, keychains, browser data, mail and messages, shell history, other agents' configuration, enclos's protected paths and other sandboxes). It can write only to its own home and to workspaces the user explicitly grants. The agent may install skills, dependencies and tools on its own, so the home provides writable space for environments, executables, caches and skills, and programs it installs there may run. What those programs can do is still limited by the filesystem and network policy.

The shared runtime (`runtimes/`) is read-only to every sandbox (milestone 1 installs runtimes per sandbox instead: [0020](0020-runtimes-installed-per-sandbox.md)), and enclos's control files are protected ([0010](0010-sqlite-state-and-jsonl-audit.md)). Coding agents, when introduced, write directly to the selected project folder, granted as a workspace, with no copy or overlay.

## Considered options

- **Read allow-list:** stronger, but agents and the tools they install read many paths nobody can list upfront, and the threat model ([0014](0014-threat-model-accidental-damage.md)) is accidental damage, which comes mostly from writes and from credentials.
- **Program allow-list for agents that install tools:** would block the installs this decision exists to allow. `[exec]` restrictions remain available for templates that do not install anything.

## Consequences

- Anything the agent downloads from an allowed destination can run inside the sandbox.
- The deny list must be maintained, and a sensitive path missing from it is readable. `enclos policy test` probes the default entries.
- Temporary files go to a folder inside the home (`TMPDIR`), not to the system temp folders.
