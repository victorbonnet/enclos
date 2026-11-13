---
status: proposed
---

# Agent display names belong to the bridge

A person wants an agent such as `comptoir-dev` to appear as **Gégé Commit** on every connected phone. Renaming a runtime identity would change addresses, paths and channel configuration, and runtime name rules need not accept spaces or accents. Keeping a name only on one phone would disagree with another phone and disappear with its cache.

Decision (proposed): the bridge owns an optional **agent display name**, keyed by the agent's stable `<sandbox>/<agent>` identifier. The host's person may set or clear it from a still-paired device; the bridge persists the name, records the edit and synchronizes it to paired devices that can see the agent. Clearing restores the identifier as the visible fallback. Names may contain ordinary Unicode text, without invisible characters, and need not be unique, but none may be another agent's handle or address, compared without ASCII case (protocol.md says how; a look-alike in another script or fullwidth form is not caught); the canonical address remains available to distinguish agents.

App labels, including group attribution and older messages' agent headers, resolve the current display name. Routing, conversation identity, `@handles`, runtime identities, memory, prompts and native channel names remain unchanged. This is a generic bridge feature: Hermes and a future OpenClaw channel use the same contract, with no runtime rename hook.

Edits compare a nonnegative per-agent revision. A clear retains that revision, and devices keep the newest observed name so delayed lists, broadcasts or cache reads cannot undo an edit. The app waits for confirmation, offers no offline rename queue, and requires updated host support. [The protocol](../protocol.md#agent-display-names) specifies authorization, validation and conflict handling; the [app spec](https://github.com/victorbonnet/enclos-app/blob/main/docs/spec.md#agent-display-names) specifies the editor.

Reason: a shared presentation name lets a person use a human name without migrating a runtime's identity or tying the app to one runtime's naming rules.
