# Hermes native questions

Source inspection of Hermes's default branch on 2026-11-11, at commit [`b1a6350`](https://github.com/NousResearch/hermes-agent/tree/b1a6350602383fdbed9b0bd0eb15d86eaa335da8); the first inspection, on 2026-11-09, read [`e5ea5fd`](https://github.com/NousResearch/hermes-agent/tree/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6). These findings inform [ADR 0052](../adr/0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md), proposed. enclos follows Hermes's latest release rather than pinning one: CI's `hermes-latest` job runs the plugin's real-Hermes tests against the default branch, so a change to anything below fails there.

## Messaging adapter

The seam is `send_clarify(chat_id, question, choices, clarify_id, session_key, metadata=None)`. It receives one question at a time, even for a batched tool call. The default adapter renders Hermes's numbered text (`gateway.clarify.*` translations) and marks the entry as awaiting text. An adapter whose prompt is a persistent card may define `retire_clarify_card(clarify_id, notice)`, which the gateway calls when the clarify ends without a click: timeout, session reset, or prose that supersedes it. [Adapter contract](https://github.com/NousResearch/hermes-agent/blob/b1a6350602383fdbed9b0bd0eb15d86eaa335da8/gateway/platforms/base.py).

`get_pending(clarify_id)` returns the pending entry; its docstring invites adapters that render native choice cards to compare it by identity and read `session_key`, `choices` and `multi_select`. The entry's class is private (`_ClarifyEntry`), and the channel also reads its `event` and `response` to observe how it ended: a change there is caught by the real-Hermes tests, and at run time cancels the card rather than leaving it open. `resolve_gateway_clarify(clarify_id, response)` resolves that waiter directly; its registry lock makes the first answer win. Entries are in memory and disappear on timeout, interruption or process restart. The enclos adapter therefore binds a separate app id to the entry's object identity, native id, session and conversation; an answer never becomes an ordinary inbound chat turn. Persistence and reconnect reconciliation are enclos's responsibility. [Registry](https://github.com/NousResearch/hermes-agent/blob/b1a6350602383fdbed9b0bd0eb15d86eaa335da8/tools/clarify_gateway.py).

Since `e5ea5fd`, an entry also records an `authority`: who may answer it from a chat. It applies to typed replies; `resolve_gateway_clarify` does not check it, and enclos checks its own (the conversation's owner on a paired device) before resolving.

## Waiting time

`resolve_clarify_timeout` reads `agent.clarify_timeout` (or the older `clarify.timeout`) from the profile's `config.yaml`. Its default fell from 3600 s at `e5ea5fd` to 90 s: "an unanswered question frees the turn quickly". A question in the app is often read later, on a phone, so `runtime configure` sets `agent.clarify_timeout` to 3600 s for the app's agents (`CLARIFY_TIMEOUT_SECONDS` in `src/runtime/hermes.rs`). A reply typed instead still cancels the question at once.

## Typed replies

The text interceptor resolves the oldest pending entry of a session. A number, an option's exact text, or "skip" answers a choice question; on a multiple-choice one, several separated by commas or spaces. Other prose either answers, when the entry awaits text (an open question, or after the default adapter's numbered text), or cancels the question and is handled as a follow-up message. The enclos channel leaves a native card's entry as Hermes made it, so prose in the composer cancels it, and the app's Other answers through `question.answer` instead. The channel's text fallback is Hermes's own, which awaits text. [Coercion](https://github.com/NousResearch/hermes-agent/blob/b1a6350602383fdbed9b0bd0eb15d86eaa335da8/tools/clarify_gateway.py).

## Agent call and result

The `clarify` schema uses `questions: [{question, choices?, multi_select?}, ...]`, with 1–5 questions and at most four choices each. Labels may be up to 8000 characters. Hermes marks the first of two or more choices `(Recommended)`. Options belong in `choices`; the UI supplies Other. Native messaging presents a batch sequentially, without exposing a batch id or total to the adapter. [Tool schema and result normalization](https://github.com/NousResearch/hermes-agent/blob/b1a6350602383fdbed9b0bd0eb15d86eaa335da8/tools/clarify_tool.py).

The adapter passes one canonical label for a single choice, a JSON array of labels in definition order for multiple choices, and the person's text for Other or an open question. Skip maps to the imported `SKIPPED` sentinel; `CANCELLED` is reserved for native cancellation. App text must reject NUL-prefixed sentinel injection: the app, bridge and channel refuse every hidden character (enclos-protocol's `visible` rule), newlines aside.

## Skill discovery and compatibility

Plugin skill files are registered explicitly with `ctx.register_skill`; they are not discovered just because a plugin contains `SKILL.md`. Registration qualifies the name as `enclos:app-questions`. The platform hint keeps essential tool guidance available when an older plugin context has no registrar. The native functions and the bridge's `questions` capability are feature-detected; a missing function is logged once, and questions go as text. [Skill registrar](https://github.com/NousResearch/hermes-agent/blob/b1a6350602383fdbed9b0bd0eb15d86eaa335da8/hermes_cli/plugins_content.py).

## Verification boundary

Adapter tests use the real checkout's registry, resolver and clearing functions with an Event waiter, alongside isolated bridge socket/store and Android UI/cache tests. They do not start a model turn, run a live gateway, change a sandbox or install the app on a phone. End-to-end gateway and device checks remain in the design's verification list.
