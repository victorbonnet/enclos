---
status: proposed
---

# An agent's model is changed through its runtime's channel

Amends [0031](0031-a-service-restarts-when-its-runtime-settings-change.md) for settings a runtime applies on its own.

The host's person wants to choose, from the app, the model provider and model any agent of a sandbox uses (issue #325). enclos could write the runtime's settings itself, as `runtime configure --set` does, but each runtime names its model differently (Hermes's `model.default` and `model.provider`, OpenClaw's `agents.entries.<agent>.model.primary`), checks a choice in its own way (credentials, aliases, the provider's catalogue), and alone knows which providers the agent can use and which models they offer, from logins kept inside the sandbox.

Decision (proposed): the agent's model stays the runtime's setting, read and changed through an optional `model` capability of the agent's channel, as routines are ([0050](0050-routines-stay-with-the-runtime.md)). The plugin lists the providers and models with the runtime's own catalogue, marks those the agent cannot use yet, and saves a choice with the runtime's own code. The bridge lets only the host's person ask, on a still-paired device, refuses a change made against a stale revision, never queues one, and records each change in its log. It applies to every agent, for all its conversations.

A runtime's service often serves every agent of a sandbox, so the restart of 0031 would drain and restart them all for one agent's model. A runtime adapter therefore says which part of a settings file needs a restart when it changes (`restart_relevant`); the watch compares that part only. Hermes reads its `config.yaml` again for each turn's model, so its adapter leaves out the top-level `model` block, and compares the whole file when its YAML is beyond the adapter's small reader. OpenClaw's adapter watches no settings file: its own config write hot-applies a model change.

Reason: the runtime is the only place that knows the catalogue, the credentials and how to save a model safely; enclos stays runtime-agnostic by carrying a typed request, and restarts only for what needs it.

## Consequences

- No credential travels the protocol: a provider the agent cannot use is shown with what to do on the host.
- A model change applies on the agent's next turn without restarting the others, as Hermes's and OpenClaw's source say; that a running gateway picks it up is to verify on a real host (design §14).
- A change elsewhere in a Hermes `config.yaml` still restarts the gateway, as 0031 decided. Hermes saves by writing the whole file again, so one last edited by hand may come back reformatted, comments gone, and restart the gateway once.
- A model set inside one conversation (a runtime's `/model` command) still overrides the agent's model there, as the runtime decides.
