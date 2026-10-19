---
status: accepted
---

# The sandbox is the permission boundary, the agent is not

Each sandbox holds one runtime and any number of its agents. All agents in a sandbox share its policy, proxy and home folder, so they can read each other's files. Agents that need different permissions go in different sandboxes. Enforcing permissions per agent inside one sandbox would mean a separate sandbox per agent anyway, so enclos makes that explicit instead of offering a boundary it cannot hold.

## Consequences

- The network log is per sandbox, not per agent ([0024](0024-agents-reached-through-the-runtime.md); a per-agent listener was planned first).
- Secrets are granted per sandbox ([0022](0022-secrets-granted-per-sandbox.md)): every agent's session and the runtime's gateway receive the same variables. Agents that must not share a secret go in different sandboxes.
