---
status: proposed
---

# The host's person speaks to OpenClaw with its owner authority

Amends [0060](0060-the-bridge-signs-runtime-approval-decisions.md), whose key signed nothing but runtime-approval decisions and whose `message.in` granted nothing.

OpenClaw keeps some tools for its "owner": `automations` (its scheduled jobs), its own settings and a few session tools. A turn has that authority only when its sender is named in `commands.ownerAllowFrom`, as `<channel>:<sender>`, or comes from one of OpenClaw's own admin clients; a channel plugin cannot grant it per message. enclos's channel passes every person as an ordinary allowed sender, and enclos writes no owner, so no message from the app is ever the owner's. An OpenClaw agent asked from its Home to look at or change its schedules is refused, while a Hermes agent does it. The `host` flag of a `message.in` cannot be the proof: it is not signed, and any program holding the agent's token can speak on the plugin's socket and say `host: true` ([0060](0060-the-bridge-signs-runtime-approval-decisions.md)).

Decision (proposed):

- **The bridge signs the host's person's messages.** When it gives a plugin a message the host's person sent from a paired device, in a direct conversation (Home included) and with no attachments, the bridge signs it as it sends it, with its runtime-approval key under a second label, `enclos/host-message/1`. The statement is the label, the agent (`sandbox/agent`), the conversation, the message's id, the person, the text and the signing time, each after its length; the `message.in` carries `signed: {at, sig}`. A group turn, another person's message, `enclos app chat` and a message with files are never signed. The key now signs two statements, which their labels keep apart; it signs nothing else.
- **OpenClaw's channel gives a signed message the owner's sender.** The plugin checks the signature, with the key 0060 already gives it, over the message as it received it, made within the last 60 seconds. A message that verifies is passed to OpenClaw from the sender `host`; any other keeps its person as its sender, and one whose person is `host` or `enclos:host` is refused before it binds a conversation, so that no unsigned message can take that sender. A receipt makes a message's id count once, so a replayed message changes nothing.
- **enclos names that sender OpenClaw's owner.** `enclos runtime configure <sandbox>/<agent> --channel app` adds `enclos:host` to the sandbox's `commands.ownerAllowFrom` when it is missing, after the account's other settings and just before enabling it, with OpenClaw's own compare-and-set, and keeps every other entry, such as a Telegram owner. Removing the entry takes the authority away at the next turn, as OpenClaw checks it at each one, until the channel is configured again.

The Hermes plugin ignores the signature for now: a Hermes agent already manages its schedules from the app.

**The trust assumption** is 0060's: the signature stops a program that speaks on the plugin's socket; it does not stop an agent that rewrites the plugin, its settings or OpenClaw's, which [0014](0014-threat-model-accidental-damage.md) accepts.

Reason: OpenClaw's owner is the person a bot belongs to, writing on their own channel, which the host's person in a direct conversation is. The bridge already holds a key no sandbox reads and the plugin already trusts, so a second label proves the person without a new secret or a new setting. Naming a fixed sender, not the person, keeps the person's identity out of the sandbox's settings and the entry the same when the host's person changes.

Considered options: writing the host's person into `commands.ownerAllowFrom` with no signature, which also makes `enclos app chat` and group turns the owner's and is what 0060 refused for typed approvals; and a key of its own, which needs a second public key in every channel's settings for no separation the label does not already give.

## Consequences

- In those turns the agent can create, change and remove its runtime's scheduled jobs and change OpenClaw's settings, also when a page or file it reads that turn steers it there. The sandbox's policy still bounds what it reaches; its spending is bounded only by its model provider and accounts.
- Once an owner is named for the channel, OpenClaw runs its text commands (`/model`, `/new` and the like) only for the owner: other persons, `enclos app chat` and group turns may still use `/reset`, not the others. OpenClaw reads an `<channel>:` entry for that channel alone, so another channel's commands, such as a Telegram account's, do not change. Both are read from OpenClaw 2026.11.5's source.
- A message with files is not the owner's until the statement covers its attachments.
- That a running OpenClaw gateway grants `automations` to a signed Home message, and refuses it to an unsigned one, is to verify on a real host (design §14).
