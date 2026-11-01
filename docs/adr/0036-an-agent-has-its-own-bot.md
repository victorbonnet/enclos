---
status: accepted
---

# An agent has its own bot, through a secrets file of its own

Amends [ADR 0022](0022-secrets-granted-per-sandbox.md): a secret may also be granted to one agent, for routing, not isolation.

[ADR 0032](0032-a-sandbox-has-one-bot-per-channel.md) gave a sandbox one bot per channel, its built-in agent's, so two agents that each need a bot cost two sandboxes, each with its own Hermes install, login and gateway. Two things settled what it left open:

- **Read in Hermes 0.22.5's source:** the gateway's secrets file ([ADR 0034](0034-a-service-reads-its-secrets-from-a-file-its-sandbox-alone-reads.md)) is applied last, overriding, to every agent's secret scope (`build_profile_secret_scope`). A token there reaches every agent alike, and the gateway then refuses the duplicates.
- **Shown by a prototype** (issue #107, macOS 26.5.2): an agent's own secret source, `secrets.command` in its `config.yaml`, gives that agent alone what the helper prints. In one sandbox, `main` and `scout` each read their own `TELEGRAM_BOT_TOKEN` from a file through it. The one gateway connected both bots, and each bot was answered by its own agent.

Decision: a policy grants a secret to one agent under `[secrets.agents.<agent>]`, as `env` does for the whole sandbox:
- While its services run, `enclos launch` writes each agent's granted secrets to `<sandbox dir>/secrets/<agent>.env`, beside the sandbox's own `.env`, each value written as Hermes's `secrets.command` reader takes it back. The file goes on every stop and on `sandbox rm`.
- `runtime configure <sandbox>/<agent>` points that agent's `secrets.command` at its file (`<sandbox>` alone is the built-in agent), then sets each `--set KEY=VALUE` with the runtime's own command, a secret only as `${VAR}`, so any channel or setting needs no code of enclos's; `--channel telegram` is a preset of those settings.
- `agent add` clones a new agent from the built-in one, so it starts on its model, and turns off the `secrets.command` the clone copied.
- A variable granted to the whole sandbox cannot also be granted to an agent, since the sandbox-wide file would override the agent's. Bot tokens therefore go to agents, never sandbox-wide.

Reason: a bot per agent then costs nothing more than the agent. The token still lives in the Keychain, and on disk only outside the sandbox's home, while the services run, as for the sandbox's own secrets. The route is Hermes's own per-agent secret source, meant for this, not a list it keeps for settings that are not secrets.

The cost: agents of one sandbox share its files, so any agent, and anything run in the sandbox, can read another agent's secrets file, or change its own `secrets.command`. Bots are kept apart per agent for routing, not isolated from each other. Isolation stays per sandbox, and agents that must not reach each other's secrets go in sandboxes of their own.
