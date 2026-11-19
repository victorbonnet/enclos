---
status: proposed
---

# A runtime's task events reach the app as task lines

When an agent asks for a task on Hermes's kanban board from a conversation, Hermes subscribes that conversation to the task. For each later event (a block, a completion, a give-up, a move to triage) it wakes the agent and sends the conversation a text ping in a fixed wording, its reason clipped to 160 characters, often mid-word (`gateway/kanban_watchers_notifier.py`). The ping reaches the plugin's `send()` like anything the agent says. On Hermes 0.23.2 its `metadata` holds only the subscription's routing keys, so the app showed it as a message the agent sent on its own: the tasks of a built-in agent and six specialists sharing one board filled its Home with these, one of them saying "needs a human decision" for a question the person had nothing to do with (#332). Hermes records `delivery_mode` `notify+wake` for every subscription a gateway conversation makes (`tools/kanban_tools.py`, `_resolve_notify_target`); `wake` would skip the ping, but the plugin cannot ask for it.

Decision (proposed):

- **A task event** is a change of a task that its runtime announces to a conversation. The plugin sends it as a message of its own kind, `task_event`, that names the task by its reference (as in `task.get`), its title, its assignee and what happened (blocked, gave up, crashed, timed out, done, ready for review, changes requested, moved to triage, or another status change), each read from the runtime's state, never cut from the ping's text. The app draws it as one line, such as "#298 S2a · engineer · moved to triage", with **Open task** for its task sheet (`task.get`, #318), and never as a message from the agent. A bridge or device without the kind gets the ping's text as a `notify`, as today.
- **The Hermes plugin tells a ping by the runtime's state, not by its wording alone.** A text is a ping when it begins as one of Hermes's ping templates (`gateway.kanban.ping.*`, in the gateway's language: an emoji, then the board, assignee and task id) rendered for a task this conversation is subscribed to on one of the sandbox's boards (Hermes's notify subscriptions for this platform and chat). What happened is the task's latest event of the kinds Hermes pings for. Anything else stays the agent's message. When Hermes marks its pings in `send()`'s metadata, the plugin uses that instead, and enclos asks Hermes for such a field.
- The wake turn is unchanged: the agent still answers the event in the conversation, and that answer is its message.

Reason: the person needs to see that a task moved, and which one, without reading it as the agent talking to them; the board, not the ping, says what moved. Requiring both Hermes's rendered template and a live subscription keeps an agent's own sentence that happens to start like a ping a message.

## Considered options

- **Ask for `wake` delivery only.** The person would hear only the agent's reply. Rejected for now: Hermes 0.23.2 gives a gateway conversation's subscription `notify+wake` and offers the plugin no way to choose, and changing its subscription rows would make the plugin write the board, which it only reads ([0066](0066-held-tasks-stay-with-the-runtime.md), [0068](0068-tasks-and-agent-activity-are-reported-not-controlled.md)). A silent agent would also leave the person no trace of the event.
- **Match the ping's wording only, as for the runtime's notices about itself (`status`).** Rejected: an agent's own report of its tasks often starts the same way, and a task line carries an action that a `status` line must not.
