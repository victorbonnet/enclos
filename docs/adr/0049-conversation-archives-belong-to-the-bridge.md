---
status: proposed
---

# Conversation archives belong to the bridge

A person wants to set a conversation aside and restore it later, with its history intact, as Hermes's Archive action does. The app also needs this behaviour for OpenClaw and groups, whose log the bridge already owns ([0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md), [0045](0045-group-conversations-are-the-bridges-among-one-sandboxs-agents.md)); a runtime's own session archive has different hooks and lifecycle effects.

Decision (proposed): **archived is a state of the bridge's conversation**, set or cleared only by its owner, synchronized to all of that person's paired devices. The device sends `conversation.archive` with an explicit `archived` boolean; the bridge stores it and sends the conversation's metadata again. Ordinary direct and group conversations use the same operation. Home cannot be archived: it is the agent's permanent destination for scheduled output and notices ([0044](0044-each-agent-has-a-home-conversation.md)). The bridge rejects attempts to archive Home, and the app offers no Archive action for it. Home is identified independently of its visible name. An owner can still unarchive a Home archived by an older bridge; existing archived state is not migrated automatically.

Messages, attachments, names, read positions and group membership stay in place; new activity and reconnecting leave archived conversations as they are. Unarchive restores the same conversation and delivery route.

Metadata carries a nonnegative revision, defaulting to 0 for older records. Name, read-position and archive changes advance it; devices keep the highest revision, so a delayed broadcast or sync response cannot undo newer metadata already observed.

Reason: visibility belongs with the bridge's existing conversation metadata. Keeping it out of the plugin leg gives Hermes and a future OpenClaw plugin the same behaviour without mapping their session stores or calling their archive hooks. Archiving calls no runtime command, ends no session, resets no context, stops no work and removes no saved memory. It changes no runtime-native archive flag.

The app's [ADR 0006](https://github.com/victorbonnet/enclos-app/blob/main/docs/adr/0006-archived-conversations-are-a-restorable-inbox-view.md) records the active/archived views. Sync continues to include archived metadata and history: an archive is a visibility choice, not a deletion or access boundary.
