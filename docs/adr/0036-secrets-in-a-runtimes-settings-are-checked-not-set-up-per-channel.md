---
status: proposed
---

# Secrets in a runtime's settings are checked, not set up per channel

`enclos runtime configure <sandbox> --channel telegram` sets up one channel of one runtime: it runs Hermes's own `config set` commands with the token as a `${VAR}` reference, after checking that the policy grants `VAR`, that no token sits in plain text in the built-in agent's `.env`, and that the policy reaches `api.telegram.org`. Every other channel Hermes serves, and every other setting that needs a secret, is set up with the runtime's own commands through `enclos connect` ([0024](0024-agents-reached-through-the-runtime.md)), with none of those checks. Hermes's own setup writes the secrets it asks for in plain text into the sandbox home, where any process of the sandbox and any backup of the home reads them, against [0022](0022-secrets-granted-per-sandbox.md). Adding a command for each channel would take adapter code for each channel of each runtime, kept up with each runtime release, and would still miss whatever a person or the runtime's setup writes by hand.

Decision (proposed): enclos checks secrets where the runtime keeps its settings, whoever wrote them, and does not set up channels one by one. `enclos doctor` reads the runtime's settings files in the sandbox home, the ones [0031](0031-a-service-restarts-when-its-runtime-settings-change.md) watches, as other files of the home are read ([0023](0023-agents-made-inside-a-sandbox.md)), and reports, by file, line and name, never by value: a value in plain text under a name the active policy grants, or whose last word says it holds a secret (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`); and a `${VAR}` reference to a variable the active policy does not grant. The docs give one way to set up any channel or setting that needs a secret: `enclos secret set`, a grant in the policy, `enclos policy allow` for its host, and the runtime's own command through `enclos connect` with `'${VAR}'`. Once this is accepted, `runtime configure --channel` is removed; `runtime configure` stays only for typed settings that work the same for every runtime, as 0024 allows. [0032](0032-a-sandbox-has-one-bot-per-channel.md)'s refusal of an agent's own bot then becomes guidance in the docs, since enclos cannot refuse what the runtime's own commands do.

Reason: a check of the settings catches a secret however it got there, through the runtime's setup, by hand, or for a channel enclos has never heard of; one recipe and two checks cost less than an adapter entry for each channel and each runtime release, and keep enclos to what 0024 gives it.

## Consequences

- The `doctor` checks come first, without waiting for this ADR: they are reported, and `doctor` still exits 0 for them, as for a compiled policy that changed.
- The check by name is a guess: a secret under another name, or spread over several lines of YAML, is missed, and a setting named like a secret that is not one is reported.
- What `runtime configure` knows about Telegram moves into the docs: that Hermes keeps `TELEGRAM_BOT_TOKEN`, and not another name, out of its agents' commands, and that the bot should be told who it answers before it is turned on.
- A first bot takes four commands rather than one.

## Considered options

- **A command for each channel**, as Telegram has: checks before anything is written, but one adapter entry for each channel and runtime, and nothing for settings that are not channels.
- **A generic `runtime configure --set KEY=VALUE --secret KEY=VAR`**, with the same checks for any key: works for every setting, but stands in for `hermes config set`, against 0024, and still misses what the runtime's setup writes on its own.
- **Keep `runtime configure --channel` beside the checks**: one command for the most common channel, at the cost of the adapter code and a second way to do the same thing.
