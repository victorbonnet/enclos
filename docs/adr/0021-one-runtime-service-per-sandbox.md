---
status: accepted
---

# One runtime service per sandbox, not one per agent

The design gave each agent its own background service. Hermes runs one gateway per Hermes home, and that one gateway serves every agent: `hermes -p <name> gateway run` refuses while none runs, and the default gateway handles every agent's scheduled jobs and, later, messaging (prototype, issue #5). So a sandbox has at most two launchd agents while the user is logged in: `enclos.<sandbox>.proxy`, and `enclos.<sandbox>.gateway`, which runs the runtime's background command under the sandbox's compiled policy through `enclos launch`. People talk to each agent with `enclos connect <sandbox>/<agent>`, an interactive session beside the gateway.

## Consequences

- `sandbox start` installs both and they come back at each login; `sandbox stop` removes both. There is no per-agent start or stop.
- Agents still get their own proxy listener, so `net log <sandbox>/<agent>` stays per agent for interactive sessions. The gateway's traffic is logged under the sandbox.
- A runtime with one service per agent would need a new decision.
