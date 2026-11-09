---
status: proposed
---

# Group conversations are the bridge's, among one sandbox's agents

A person wants to talk to several agents at once, in one conversation: ask them all, or one by `@` name, and let them answer each other. Hermes has this ("hosted rooms": profiles of one install share a room, one turn at a time, `@handle` and `@all`, an agent may pass, rounds bounded at 3 and replies at 10), but it runs in Hermes's own desktop server, which enclos does not run, on Hermes internals that change between releases, and only for Hermes.

Decision (proposed): **the bridge keeps group conversations and runs their turns**, with Hermes's rooms as the reference semantics:

- **Members are agents of one sandbox**, two to six. A sandbox is enclos's boundary: a group across sandboxes would carry one sandbox's conversation into another's, which nothing else in enclos does. One sandbox is also one runtime install, as Hermes's rooms require.
- **One log**: a group is a conversation of the bridge with several members, its messages in the same ordered store as any other, each agent message with its speaker. Each member keeps its own session for the group in its runtime, apart from its one-to-one conversations: the plugin is given the group's id, which Hermes keys its sessions by, per profile.
- **Addressing** by handle, the agent's name in its sandbox: `@main`, several, `@all` or `@everyone`; none addresses every member. An agent's reply that mentions another member asks it for a follow-up turn.
- **Turns** one at a time per group, run by the bridge, which sends each member, as a person's message to it, the group's messages it has not seen (at most 24, with who said each) and the group's rules. A member may answer `(pass)`, unless the person addressed it by name or with `@all`, which asks every member for an answer. A discussion ends **settled** when a round brings no new message, or **bounded** after 3 rounds or 10 agent messages.
- **Durable and resumable**: messages, turns and each member's position are in the bridge's database; a new message waits behind the group's work; Stop cancels the work, not the history; a device that reconnects gets the group's state with the log.

Reason: the bridge already owns the conversations, their order, their owners and the connection to every agent, so it can hold a group's log and schedule its turns for any runtime with a plugin, keep running while the phone is away, and keep the sandbox boundary, with nothing added to the plugin leg.

## Consequences

- A member's session for the group is an ordinary session of its runtime (Hermes: a chat of the app's platform), seen in its session list, where Hermes's rooms keep a hidden one.
- The bridge cannot hold a member's turn in a group behind the same member's turn in a one-to-one conversation, as Hermes's per-profile lock does: the runtime gets both, and Hermes serializes or not as its gateway does.
- Stop sends the member `/stop` when its turn is running, as the person would; a runtime without such a command finishes the turn, whose reply the bridge then drops.
- Mentions are not checked by any runtime: an agent that writes another member's handle wakes it. The bounds keep that finite.
