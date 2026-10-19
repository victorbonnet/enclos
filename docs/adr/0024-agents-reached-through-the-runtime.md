---
status: accepted
---

# Agents are reached through the runtime's own commands, with one proxy port per sandbox

The first design had enclos address agents itself: `enclos connect <sandbox>/<agent>` opened that agent's interface, and each agent had its own proxy port, so the network log could say which agent made a connection. In use, that made two ways to reach an agent (`enclos connect lab/scout` and the runtime's own `scout`), the first needed per-runtime code for every way an agent can be used, and the attribution held only for sessions enclos started for an agent: the gateway serving every agent, and anything run from a shell, used the sandbox's port anyway.

So `enclos connect <sandbox>` is the only way into a sandbox: a shell, or the command after `--`, which is the runtime's own (`enclos connect lab -- scout model`, `enclos connect lab -- hermes -p scout`). enclos does not need to know how a runtime selects an agent. Each sandbox has one proxy port, and the network log is per sandbox. `<sandbox>/<agent>` names an agent only in the commands that manage agents (`enclos agent add` and `rm`).

This supersedes the per-agent listener and per-agent network log in [0003](0003-sandbox-is-the-permission-boundary.md), [0007](0007-network-through-a-proxy-per-sandbox.md) and the design's first draft.

## Consequences

- The network log no longer says which agent made a connection. That attribution was informative only ([0003](0003-sandbox-is-the-permission-boundary.md)); the sandbox stays the boundary.
- Adding or removing an agent changes neither the compiled policy nor the proxy, which no longer restarts.
- Typed settings that work the same for every runtime (`enclos runtime configure … --model`) can still come later; they would name an agent as `<sandbox>/<agent>` like the agent commands.
- If a per-agent network log matters later, a runtime adapter could point each agent at its own port through the runtime's own per-agent configuration; that needs a new decision.
