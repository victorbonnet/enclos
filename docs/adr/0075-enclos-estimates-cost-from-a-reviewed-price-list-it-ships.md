---
status: proposed
---

# enclos estimates cost from a reviewed price list it ships

Context: usage (issue #282) shows each agent's tokens, and the runtime's own cost where it keeps one. Hermes prices calls from a snapshot of its own; OpenClaw has its own; a runtime may price nothing. So the same model could cost two amounts in two sandboxes, or none, and the bridge and the app, which see only token counts, could show no cost at all. Issue #343 asks for an estimated cost per agent and per sandbox, by day, in the CLI and the app.

Decision: enclos prices usage itself, from one price list for every runtime: US dollars per million tokens per model provider and model, shipped inside enclos (`src/prices.toml`). A part is kept by hand and wins; the rest is generated from a pinned commit of LiteLLM's price file by a script, which a weekly workflow runs and turns into a pull request that a person reviews. enclos fetches no price when it runs. A file in the user's config folder overrides it. A model it has no price for costs unknown, never $0; a model provider it marks `included` is a subscription, whose tokens are still priced at their model's list price as if paid, beside the word included, so an agent heavy on a subscription shows as heavy. The estimate is worked out when usage is read, so a corrected price applies to past usage. The runtime's own figure is still shown beside it.

Reason: one list makes costs comparable across runtimes and sandboxes, and lets the bridge price what a plugin reports, which carries no cost. Shipping it, rather than fetching it, keeps enclos making no network call of its own and keeps every price change in a reviewed commit; a list a week old is close enough for an estimate. LiteLLM's file covers the model providers runtimes use and is kept current by many; the hand part corrects it where it is wrong. Estimating from tokens is an estimate only: the counts come from inside the sandbox, and long-prompt rates, batch prices and cache lifetimes are not applied.

## Considered options

- The runtime's cost alone: no cost where the runtime keeps none, none at all in the app, and different prices for one model.
- Fetching prices when enclos runs: current, but a network call enclos makes on its own, and prices no one reviewed.
- Copying openvigie's list by hand: the same source a step removed, with no update of its own.
