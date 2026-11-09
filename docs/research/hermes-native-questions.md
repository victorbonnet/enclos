# Hermes native questions

Source inspection on 2026-11-09, pinned to Hermes commit [`e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6`](https://github.com/NousResearch/hermes-agent/tree/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6). These findings inform [ADR 0052](../adr/0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md), proposed.

## Messaging adapter

The public seam is `send_clarify(chat_id, question, choices, clarify_id, session_key, metadata=None)`. It receives one question at a time, even for a batched tool call. The default adapter renders numbered text. The matching `retire_clarify_card` hook receives notices for typed answers, timeout and cancellation. This is a messaging channel, distinct from the local viewer's full-batch request API. [Adapter contract](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/gateway/platforms/base.py), [messaging turn runner](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/gateway/run_turn_runner.py).

`get_pending(clarify_id)` exposes the native entry, including session, choices, multiple-selection mode and event. `resolve_gateway_clarify(clarify_id, response)` resolves that waiter directly; its registry lock makes the first answer win. Entries are in memory and disappear on timeout, interruption or process restart. The enclos adapter therefore binds a separate app id to the entry's object identity, native id, session and conversation; an answer never becomes an ordinary inbound chat turn. Persistence and reconnect reconciliation are enclos's responsibility, not native waiter recovery. [Registry and text coercion](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/tools/clarify_gateway.py).

## Agent call and result

The current `clarify` schema uses `questions: [{question, choices?, multi_select?}, ...]`, with 1–5 questions and at most four choices each. Labels may be up to 8000 characters. Hermes adds `(Recommended)` to the first of two or more choices. Options belong in `choices`; the UI supplies Other. Native messaging presents a batch sequentially, without exposing a batch id or total to the adapter. [Tool schema and result normalization](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/tools/clarify_tool.py).

The adapter passes one canonical label for a single choice, a JSON array of labels in definition order for multiple choices, and the person's text for Other or an open question. Skip maps to the imported `SKIPPED` sentinel; `CANCELLED` is reserved for native cancellation. App text must reject NUL-prefixed sentinel injection. The text interceptor also accepts numeric or exact-label replies from older apps. Marking the native card as awaiting text enables a custom typed reply while preserving that selection coercion. [Registry/interceptor](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/tools/clarify_gateway.py), [inbound handling](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/gateway/run_inbound.py).

## Skill discovery and compatibility

Plugin skill files are registered explicitly with `ctx.register_skill`; they are not discovered just because a plugin contains `SKILL.md`. Registration qualifies the name as `enclos:app-questions`. The platform hint keeps essential tool guidance available when an older plugin context has no registrar. Required native APIs and the bridge's `questions` capability are feature-detected; unsupported cases retain the base text path. [Skill registrar](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/hermes_cli/plugins_content.py), [plugin content discovery](https://github.com/NousResearch/hermes-agent/blob/e5ea5fd9ccdf2913c0b21b24eb3d22b321d2e2a6/hermes_cli/plugins.py).

## Verification boundary

Adapter tests use the real checkout's public registry, resolver and clearing functions with an Event waiter, alongside isolated bridge socket/store and Android UI/cache tests. They do not start a model turn, run a live gateway, change a sandbox or install the app on a phone. End-to-end gateway and device checks remain in the design's verification list.
