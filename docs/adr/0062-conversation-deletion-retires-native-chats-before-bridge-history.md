---
status: proposed
---

# Conversation deletion retires native chats before bridge history

The bridge keeps the person's transcript while each agent keeps native session context. Erasing only the bridge copy leaves runtime history behind; erasing the bridge copy first also prevents a failed native deletion from being retried reliably. A group can involve several native chats, which cannot be removed in one transaction.

Decision (proposed): the owner confirms permanent deletion of an ordinary direct or group conversation; Home is protected. The bridge reserves its id, blocks new turns, and requests native deletion through the channel's `conversation_delete` capability. It checkpoints each completed target and removes its history and files only after all targets confirm. A runtime's authoritative absence check may establish that a removed agent has no data left; absence from the bridge's channel list is insufficient, especially after `agent rm --keep-data`. Partial or ambiguous native outcomes remain reserved and explicitly retryable; they are not automatically restored as usable context.

Only the owner and id remain after completion. They prevent id reuse and delayed frames from resurrecting a conversation and inform every paired device at sync, including one reconnecting after all removed message sequences. These records are retained until a future protocol can establish that every relevant device has durably observed deletion; a message cursor alone cannot prove that. The trade-off is permanent id retention and sync work proportional to deletion history. A bounded worker performs native round-trips without holding the phone's connection loop, and final removal is logged with its device and person. Agents, saved memory and routines remain.
