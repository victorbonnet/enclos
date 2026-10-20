---
status: accepted
---

# One runtime service per sandbox, not one per agent

The design gave each agent its own background service. Hermes runs one gateway per Hermes home, and that one gateway serves every agent: `hermes -p <name> gateway run` refuses while none runs, and the default gateway handles every agent's scheduled jobs and, later, messaging (prototype, issue #5). So services belong to the sandbox, not to its agents: the sandbox's proxy, `enclos.<install>.<sandbox>.proxy`, and the background services its runtime adapter declares, each under a stable name, `enclos.<install>.<sandbox>.<service>`, which runs the declared command under the sandbox's compiled policy through `enclos launch <sandbox> <service>`. Hermes declares one, `gateway`, run with `--external-supervisor` so that it exits for launchd to restart it rather than starting a replacement no session holds. People talk to each agent with the runtime's own commands through `enclos connect <sandbox> -- …`, an interactive session beside the gateway ([0024](0024-agents-reached-through-the-runtime.md)).

## Consequences

- `sandbox start` installs them and they come back at each login; `sandbox stop` removes them. There is no per-agent start or stop.
- A runtime with several background components declares each; the core's start, stop, status and logs handle any number. A runtime with one service per agent would also need the sandbox's agents as input, and a new decision.
