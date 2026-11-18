---
status: proposed
---

# The host's person can forget a removed agent

Removing an agent or its sandbox on the host leaves the person's conversations with it on the bridge. [0062](0062-conversation-deletion-retires-native-chats-before-bridge-history.md) (proposed) lets the app delete an ordinary direct or group conversation, including one with a removed agent, but never Home: [0044](0044-each-agent-has-a-home-conversation.md) (proposed) makes Home the agent's permanent destination and [0049](0049-conversation-archives-belong-to-the-bridge.md) (proposed) forbids archiving it. Both assume the agent still exists. Once it is gone, its Home receives nothing, yet stays at the top of Agents with no way to clear it. On a Mac, after `sandbox rm` of a sandbox with two agents, their two Homes stayed in the app for good, beside one agent's 24 direct conversations that had to be deleted one by one.

Decision (proposed):

- **Forget is one action on a removed agent**, from its page in the app. It permanently deletes the agent's Home and every direct conversation the host's person has with it. Groups the agent was in stay, each deleted on its own under 0062, because they hold other agents' chats.
- **Only a removed agent can be forgotten.** The bridge uses 0062's check: the runtime's no-follow identity and folder checks find no native identity or data, as after `sandbox rm`. A missing channel, a removed record, `agent rm --keep-data` or a folder enclos cannot read is not enough, and the bridge refuses. The bridge tells the app which agents it has confirmed removed, and the app offers Forget only for those and only when the bridge announces the capability.
- **Only the host's person forgets**, from a still-paired device, because Home is theirs (0044). Another person's conversations with a removed agent stay theirs, to delete under 0062.
- **Each conversation is deleted as under 0062**, with no native round-trip, since nothing native is left: its id is kept as a deletion record, every paired device hears of it at sync, and its messages, files, questions and turns are removed. The bridge's log records one forget entry with its device, person, agent and every conversation id.
- **A forgotten Home's id is never used again.** If an agent with the same sandbox and name is made later, its Home gets a new id the bridge chooses, which `enclos runtime configure --channel app` writes and the bridge names in its `hello`, instead of the fixed `home.<sandbox>.<agent>`.

Reason: a removed agent has no use for a destination, so keeping its Home only leaves rows the person cannot clear. Restricting Forget to agents the runtime's checks confirm gone keeps a Home from disappearing while its agent can still send to it. Taking the Home and the direct conversations together avoids an agent shown with conversations but no Home, a state the app does not have. A new id for a later Home is the cost of 0062's deletion records, which devices keep for good and use to ignore anything later sent under the same id.

## Considered options

- **Delete Home on its own once its agent is removed.** Rejected: it leaves the agent's other conversations without the Home its page opens.
- **Forget automatically when the sandbox or agent is removed.** Rejected: it would erase the person's history without asking, the bridge may not be running then, and `--keep-data` means the agent may come back.
- **Delete the rows from the bridge's database.** Rejected: devices drop a conversation only on a deletion record, so phones would keep showing it, and nothing would be logged.
- **Reuse `home.<sandbox>.<agent>` for an agent made again.** Rejected: devices that saw the deletion record ignore that id for good.
