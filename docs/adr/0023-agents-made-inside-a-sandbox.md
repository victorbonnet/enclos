---
status: accepted
---

# Agents made inside a sandbox are reported, and adopted only when asked

A sandbox's home is writable by design, so anything run inside it can use the runtime's own commands to create or delete agents (`hermes profile create` in an `enclos connect` shell). enclos would not know about them: no record, so `agent list` and `sandbox show` would not show them, and `enclos agent add` would fail to create one that exists. They work anyway, under the same policy, since the sandbox is the boundary and an agent is not ([0003](0003-sandbox-is-the-permission-boundary.md)); what is lost is enclos's view of them.

So each runtime adapter can list the agents its runtime has in a sandbox home, read on the host without running anything. enclos compares that list with its records whenever it shows agents (`agent list`, `sandbox show`), after every `enclos connect` session, and when a name is not found. It reports agents it does not track, names it cannot use as agent names, and tracked agents the runtime no longer has, each with the command that fixes it. `enclos agent add` adopts an agent the runtime already has: it records it without creating it again. It never adopts or removes anything on its own.

## Considered options

- **Adopt automatically at the end of a session:** fewer steps, but adopting changes state (a record and an audit entry), and enclos changes state only on a command that says so.
- **Ignore agents enclos did not create:** simplest, but leaves `agent add` failing on an existing agent and the user unaware of agents the gateway serves.

## Consequences

- Reading happens only inside sandboxes enclos created; it is not discovery on the host, which stays out of scope.
- What the adapter reads is written by the sandbox, so it is untrusted: an adapter never follows a link, reads a bounded number of entries, and answers "cannot tell" rather than guess. A wrong answer can only mislabel an agent in a report, since adopting grants nothing the sandbox did not already have.
- Each adapter follows its runtime's own rules for what counts as an agent (for Hermes, those of `hermes profile list`). A runtime update that changes them needs the adapter updated.
- Runtimes without named agents (Claude Code, Codex) answer "cannot tell", and there is nothing to compare.
