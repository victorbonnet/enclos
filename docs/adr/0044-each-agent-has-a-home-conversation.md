---
status: proposed
---

# Each agent has a Home conversation, the runtime's home channel

Runtimes send some messages to no conversation in particular: Hermes delivers to its **home channel** a cron job that has no chat of its own, `send_message` with no target, and its own notices (gateway online, shutting down, low disk, a stranger writing). A person sets that channel with `/sethome` in a chat. In the mobile app ([0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed) each conversation is its own chat, so Hermes asked for `/sethome` at the start of every new conversation, an ordinary conversation then collected its notices, and the bridge stored what came for a chat it did not know without anyone to deliver it to.

Decision (proposed): **each agent has one Home conversation**, which the bridge makes and keeps:

- Its id is fixed, `home.<sandbox>.<agent>`, so the bridge and the runtime agree without asking. `enclos runtime configure --channel app` gives it to the runtime as its home channel (Hermes: `MOBILE_APP_HOME_CHANNEL`), and the bridge names it again in its `hello` to the plugin. `/sethome` is answered, not run.
- It belongs to the host's person, as the transport names the host's own user (Tailscale: `tailscale status`), else to the first person who connects. It is named Home by that person, so the runtime's names do not replace it, and no device may start one.
- What the agent sends to a conversation the bridge does not know, or to another agent's, goes to Home.
- The runtime's notices about itself come as `kind: status`, which the app shows as a quiet line, not as the agent speaking. A cron job started in a conversation still answers in that conversation.

Reason: one well-known place for what belongs to no conversation, made by enclos, keeps the runtime from asking every new conversation for one and keeps its notices out of the person's conversations, with nothing lost on the way.

## Consequences

- Home is shown first and never hidden as empty; the person may also talk to the agent there. It cannot be archived under [0049](0049-conversation-archives-belong-to-the-bridge.md), so its notices keep a permanent destination in the active Inbox.- With sharing ([0043](0043-sharing-an-agent-is-not-hosting-it.md), proposed), Home stays the host's person's: a guest's cron jobs answer in the guest's own conversations.
- Which of the runtime's messages are notices is the plugin's call: Hermes marks none, so its plugin recognises them (to verify against each Hermes release, design §14).
