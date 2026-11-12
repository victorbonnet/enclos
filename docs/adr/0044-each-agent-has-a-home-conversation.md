---
status: proposed
---

# Each agent has a Home conversation, the runtime's home channel

Runtimes send some messages to no conversation in particular: Hermes delivers to its **home channel** a cron job that has no chat of its own, `send_message` with no target, and its own notices (gateway online, shutting down, low disk, a stranger writing). A person sets that channel with `/sethome` in a chat. In the mobile app ([0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed) each conversation is its own chat, so Hermes asked for `/sethome` at the start of every new conversation, an ordinary conversation then collected its notices, and the bridge stored what came for a chat it did not know without anyone to deliver it to.

Decision (proposed): **each agent has one Home conversation**, which the bridge makes and keeps:

- Its id is fixed, `home.<sandbox>.<agent>`, so the bridge and the runtime agree without asking. `enclos runtime configure --channel app` gives it to the runtime as its home channel (Hermes: `MOBILE_APP_HOME_CHANNEL`), and the bridge names it again in its `hello` to the plugin. `/sethome` is answered, not run.
- It belongs to the **host's person**: the person of the first device paired with `enclos app pair` at the host's own terminal, which the bridge keeps. The terminal says so before it asks to accept that device. The transport is not asked whose host this is: a tagged node has no user login, and the person at the terminal is the one who decides. Before any device is paired, Home has no owner and keeps what comes for it. It is named Home, so the runtime's names do not replace it, and no device may start one.
- Unpairing never changes the host's person, even of their last device: their Homes keep what comes until they pair again (a new phone). `enclos app host` shows the host's person; `enclos app host <person>` hands the role, and every Home with what it holds, to another person who has a paired device, in an audit entry.
- What the agent sends to a conversation the bridge does not know, or to another agent's, goes to Home.
- The runtime's notices about itself come as `kind: status`, which the app shows as a quiet line, not as the agent speaking. The plugin, in the sandbox, decides what is a notice, and an agent can send `kind: status` itself, so a `status` line is trusted no more than any agent text: plain text, with no links and no actions. A cron job started in a conversation still answers in that conversation.

Reason: one well-known place for what belongs to no conversation, made by enclos, keeps the runtime from asking every new conversation for one and keeps its notices out of the person's conversations, with nothing lost on the way.

## Consequences

- Who the host's person is never follows from a connection or from the transport, so a guest gets Home neither by connecting first nor by pairing after the host unpaired their last phone. The cost: a host's person who leaves for good hands Home on with `enclos app host`.
- Home is shown first and never hidden as empty; the person may also talk to the agent there.
- With sharing ([0043](0043-sharing-an-agent-is-not-hosting-it.md), proposed), Home stays the host's person's: a guest's cron jobs answer in the guest's own conversations.
- Which of the runtime's messages are notices is the plugin's call: Hermes marks none, so its plugin recognises them (to verify against each Hermes release, design §14).
