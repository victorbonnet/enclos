---
status: superseded by 0036
---

# A sandbox has one bot per channel, its built-in agent's

Milestone 2's acceptance scenario has two agents of one sandbox each answer on a Telegram bot of its own, each bot's token a secret of the sandbox (design §13, step 5; [ADR 0022](0022-secrets-granted-per-sandbox.md)). Read in Hermes 0.22.4's source, its gateway serves every agent in one process ([ADR 0021](0021-one-runtime-service-per-sandbox.md)), and only the built-in agent reads the gateway's environment as it is. Another agent's settings see from that environment only the variables Hermes keeps for its own tuning, such as those starting `HERMES_TELEGRAM_`, which its source marks as "NOT the token" (`agent/secret_scope.py`); any other variable it takes from a file in its own folder, or from a secret source whose helper does not see the gateway's environment either. Since [ADR 0034](0034-a-service-reads-its-secrets-from-a-file-its-sandbox-alone-reads.md), though, the gateway gets its secrets from `$HERMES_MANAGED_DIR/.env`, which Hermes's source applies last, with override, in every agent's secret scope (`agent/secret_scope.py`, `build_profile_secret_scope`): an agent's own `${VAR}` may then resolve there. That is still to verify (design §14), with what happens when several agents see the same usual token.

Decision (proposed): a sandbox has at most one bot on each channel, its built-in agent's. `enclos runtime configure <sandbox> --channel telegram` sets it up, its token one of the sandbox's secrets, which Hermes reads from the environment as the gateway starts. An agent that needs a bot of its own goes in a sandbox of its own. Within one sandbox, a later change could route some people's chats with the bot to another agent (Hermes's `gateway.profile_routes`). `runtime configure <sandbox>/<agent> --channel` is refused, saying why.

Reason: every other way either puts a secret in the sandbox home, runs a gateway per agent, or rests on a Hermes behaviour its own source says is not meant for this. One bot per sandbox needs none of them.

The cost: two agents that must each have their own bot cost two sandboxes, two logins and two gateways. Step 5 of the acceptance scenario changes to match, once this is accepted.

Considered options:
- **Grant each agent's token under a `HERMES_TELEGRAM_` name**, and point the agent's settings at it. Read from the source, this works today without breaking ADR 0021 or 0022, but it rests on a list Hermes keeps for settings that are not secrets, and that its source says is not for tokens: an update may narrow it, and the bot would then go quiet.
- **Write each agent's token into its own `.env`.** It works with Hermes as it is, and puts a secret in the sandbox home, where any process of the sandbox and any of its backups can read it, against ADR 0022.
- **One gateway per agent.** Each would get its own environment, but launchd would then run a service per agent, against ADR 0021; and the prototype showed `hermes -p <name> gateway run` refuses while no gateway of the built-in agent runs (it also reports the agent served once one does, per issue #5, cited by ADR 0021), so each would also need a Hermes home of its own.
- **Ask Hermes for a way to give an agent its token from the gateway's environment.** This is the clean fix, and it waits on upstream; enclos adapts to the runtime as it is meanwhile.
- **Each agent's token in the gateway's secrets file** (ADR 0034), referenced as `${VAR}` in the agent's own settings. Read from the source, every agent's scope sees that file; not yet run with real bots, and the reason above weighs differently if it works.
