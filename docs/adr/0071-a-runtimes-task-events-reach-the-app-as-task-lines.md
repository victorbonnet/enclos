---
status: proposed
---

# A runtime's task events reach the app as task lines

When an agent asks for a task on Hermes's kanban board from a conversation, Hermes subscribes that conversation to the task (`kanban.auto_subscribe_on_create`, on by default; `/kanban subscribe` does the same). For each later event of the kinds it reports (blocked, done, ready for review, changes requested, gave up, crashed, timed out, sent to triage by its loop breaker) it sends the conversation a text ping in a fixed wording and wakes the agent; a plain status change gets the ping without a wake (`gateway/kanban_watchers_notifier.py`). The ping's reason is clipped to 160 characters, often mid-word. It reaches the plugin's `send()` like anything the agent says, with only the subscription's routing keys in its `metadata` (checked on Hermes 0.23.1 and 0.23.2), so the app showed it as a message the agent sent on its own. On a board shared by a built-in agent and six other agents (Hermes 0.23.1, #332), these filled its Home, one of them saying "needs a human decision" about a question the person had nothing to do with. Such a subscription records `delivery_mode` `notify+wake` (`tools/kanban_tools.py`, `_resolve_notify_target`). `wake` alone would skip the ping, but the plugin could get it only by rewriting the subscription row (`hermes kanban notify-subscribe --delivery-mode wake`).

Decision (proposed):

- **A task event** is a change of a task that its runtime announces to a conversation. The plugin sends it as a message of its own kind, `task_event`, that names the task by its reference (as in `task.get`), its title, its assignee and what happened (blocked, gave up, crashed, timed out, done, ready for review, changes requested, sent to triage, or another status change), each read from the runtime's state, never cut from the ping's text. The app draws it as one line, such as "t_3f9a12bc S2a · reviewer · sent to triage", with **Open task** for its task sheet (`task.get`, #318), and never as a message from the agent. A bridge or device without the kind gets the ping's text as a `notify`, as today.
- **The Hermes plugin tells a ping by the runtime's state and its wording together, now.** A text is a ping when it begins as one of Hermes's ping templates (`gateway.kanban.ping.*`, read in the language of the context `send()` runs in: an emoji, then an optional `[board]` and `@assignee`, then `Kanban <task id>`) rendered for a task this conversation is subscribed to on one of the sandbox's boards (Hermes's notify subscriptions for this platform and chat). What happened is the oldest event of that ping's kind that Hermes claimed for the subscription and has not yet recorded as pinged (`last_ping_event_id`, written once `send()` returns), so the agent's later words that repeat a ping stay its message. Anything else stays the agent's message.
- **enclos asks Hermes to mark its pings** in `send()`'s metadata (the task, the event and its kind), as it already marks lifecycle sends for Discord. The plugin uses that mark as soon as a Hermes release has it, and keeps the match above only for older ones.
- The wake turn is unchanged: the agent still answers the event in the conversation, and that answer is its message.

Reason: the person needs to see that a task moved, and which one, without reading it as the agent talking to them; the board, not the ping, says what moved. Matching now, instead of waiting for Hermes, follows the latest runtime without holding the app back. Requiring both Hermes's rendered template and a live subscription keeps an agent's own sentence that happens to start like a ping a message, and a Hermes release that changes the wording turns pings back into today's messages, not into wrong lines.

## Consequences

- `kind: task_event` is a new value of a fixed set, which the protocol's Versions rule would have made a version change. It is added within version 1 because a capability keeps it from every peer that did not ask for it, on both legs, which get the same message as a `notify`; [the Versions section](../protocol.md#versions) states this exception.

## Considered options

- **Ask for `wake` delivery only.** The person would hear only the agent's reply. Rejected for now: Hermes gives a conversation's subscription `notify+wake`, and getting `wake` means rewriting the subscription row. The plugin reads the board and writes it only through Hermes's own unblock, for a resume ([0066](0066-held-tasks-stay-with-the-runtime.md)). A silent agent would also leave the person no trace of the event.
- **Match the ping's wording only, as for the runtime's notices about itself (`status`).** Rejected: an agent's own report of its tasks often starts the same way, and a task line carries an action that a `status` line must not.
- **Wait for Hermes to mark its pings.** Rejected: enclos follows the latest runtime and does not wait on upstream; the mark replaces the match when it lands.
