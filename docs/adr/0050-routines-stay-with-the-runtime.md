---
status: proposed
---

# Routines stay with the runtime

The mobile app needs to manage an agent's scheduled work, as Hermes's Routines screens do. Hermes already owns its schedules, execution, output and delivery; copying them into the bridge would create two schedulers whose definitions and state could disagree.

Decision (proposed): a **routine belongs to its agent's runtime**. An optional `routines` channel capability exposes typed, correlated management requests through the bridge. The runtime keeps the definitions, validates schedules, executes work under its existing sandbox policy and reports observed run state. The phone is an editor, and the bridge authorizes and routes requests; neither schedules work. A future OpenClaw plugin can implement the same contract with its own scheduler.

Managing routines initially requires the host's person on a still-paired device, because a runtime's routine store is shared by an agent, rather than owned by an app conversation. App delivery targets are limited to that person's direct or Home conversations with that same agent. Routines with external runtime-native destinations are shown read-only, preserving those settings. Choosing a script or working directory does not widen the sandbox's policy.

Requests are live controls, not queued messages. A lost connection or timeout after dispatch can leave a mutation's outcome unknown; the app refreshes rather than automatically creating or running it again. Editable-definition revisions detect stale edits without treating scheduler changes to last/next-run times as conflicts. Runtime controls and the agent's own tools remain authoritative, including changes made outside the app.

Reason: one scheduler keeps routine execution independent of a phone or bridge connection and preserves native behaviour. A generic optional channel capability lets the app support another runtime without adopting Hermes's storage or exposing arbitrary runtime commands. This differs from conversation archives ([0049](0049-conversation-archives-belong-to-the-bridge.md)), whose state already belongs to the bridge.

The app's [ADR 0007](https://github.com/victorbonnet/enclos-app/blob/main/docs/adr/0007-routines-are-runtime-owned-controls.md) records its editor and connection behaviour. Source evidence and verification limits are in [Hermes routines research](../research/hermes-routines.md).
