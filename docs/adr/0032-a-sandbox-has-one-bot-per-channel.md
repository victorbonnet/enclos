---
status: proposed
---

# A sandbox has one bot per channel, its built-in agent's

Milestone 2's acceptance scenario has two agents of one sandbox each answer on a Telegram bot of its own, each bot's token a secret of the sandbox (design §13, step 5; [ADR 0022](0022-secrets-granted-per-sandbox.md)). Hermes 0.22.4's source says this cannot be done that way. Its gateway serves every profile in one process ([ADR 0021](0021-one-runtime-service-per-sandbox.md)). There, only the default profile reads the gateway's environment. A named profile takes a token only from its own folder's `.env`, or from a secret source configured there, whose helper does not see the gateway's environment either (`agent/secret_scope.py`, `get_secret`: "under multiplexing a miss is a miss"). Both of the ways that remain break a decision: writing the token into the profile's folder breaks ADR 0022, and a gateway of each agent's own breaks ADR 0021.

Decision (proposed): a sandbox has at most one bot on each channel, its built-in agent's. `enclos runtime configure <sandbox> --channel telegram` sets it up, its token one of the sandbox's secrets, read from the environment as the gateway starts. An agent that needs a bot of its own goes in a sandbox of its own. Within one sandbox, a later change could route some people's chats with the bot to another agent (Hermes's `gateway.profile_routes`). `runtime configure <sandbox>/<agent> --channel` is refused, saying why.

The cost: two agents that must each have their own bot cost two sandboxes, two logins and two gateways. Step 5 of the acceptance scenario changes to match, once this is accepted.

Considered options:
- **Write each agent's token into its profile's `.env`.** It works with Hermes as it is, and puts a secret in the sandbox home, where any process of the sandbox and any of its backups can read it.
- **One gateway per agent.** Each would get its own environment, but launchd would then run a service per agent, against ADR 0021.
- **Ask Hermes for a way to give a named profile a token from the gateway's environment.** This is the clean fix, and it waits on upstream. enclos adapts to the runtime as it is meanwhile.
