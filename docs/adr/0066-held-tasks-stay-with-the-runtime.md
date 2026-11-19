---
status: proposed
---

# Held tasks stay with the runtime

An agent can hand work to its runtime to run in the background, and that work can stop until a person lets it go on. On Hermes's kanban board, the dispatcher blocks a task after its retry limit, or a worker blocks it for a decision; the runtime then wakes the agent that created it with a chat turn written from the task's events. That text is not a reliable account of the task: on a Hermes default branch of 2026-11-14 (`5b229517`), a crash wake that waited behind a busy agent arrived after the task had given up, still saying "dispatcher will retry", and the next wake joined `gave_up` and `crashed` into one sentence that said both. The person then had to find the task id and type a command on the host to let it run again.

OpenClaw has no equivalent board: its 2026.11.2 release removed the Tasks and TaskFlow registry. Its closest state is a paused native subagent, which its parent or an operator resumes through the Gateway's `sessions.send`. Lobster's approval and input checkpoints are already a runtime approval or a question ([0052](0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md), [0053](0053-runtime-approvals-use-exact-native-requests-and-explicit-scopes.md)).

Decision (proposed):

- **A held task** is background work an agent's runtime started that has stopped and waits for a person before it runs again. The runtime owns it: its definition, state, retries and history. enclos keeps no second board and never runs or retries the work.
- **An optional `held_tasks` channel capability**, announced in both the bridge's and the plugin's `hello`, carries held tasks to the app. The plugin reads them from the runtime's own state, prompted by the runtime's events and read again on reconnect, never from the text of its notifications. Each carries the runtime's id for the task, its title, the agent that started the work and the one doing it, why it is held and its last error (bounded, hidden characters removed), since when, and an opaque revision.
- **The bridge keeps a card, not the task.** A held task shows as a card in the Home conversation of the agent that started the work, so it survives an app restart and can raise a notification. The plugin retires it when the task runs again, finishes or goes away, wherever that happened; reconnect reconciles pending cards, as for questions. A channel that connects without the capability has its cards expired.
- **Resume when the runtime supports it.** It is a live, correlated control from the host's person on a still-paired device, because a runtime's background work is shared by the sandbox's agents rather than owned by a conversation, as for routines ([0050](0050-routines-stay-with-the-runtime.md)). The device sends the card's id and revision; the plugin calls the runtime's own resume operation (Hermes: its kanban unblock), which changes the task only while it is still held, and answers `conflict` otherwise. It is never queued or resent automatically; after a lost reply the app refreshes. Each resume is an audit entry with its device and person. The action is optional per task: a runtime may report a task it holds but cannot resume this way as not resumable, which keeps the card held and visible, offers no Resume, and has the bridge refuse its resume, after its usual checks, before asking the plugin.
- **Resuming widens nothing.** The work runs again under the sandbox's existing policy. A task held for missing access needs a policy request, not a resume. A runtime may reset its retry budget on resume (Hermes does), and the card says what resuming does for that runtime.
- Runtimes that can report held tasks may announce the capability. This decision covers the native Resume control. [ADR 0070](0070-paired-devices-open-a-held-tasks-board-through-the-bridge.md) amends it with browser access to the runtime board, including Hermes task updates, comments and specifications for the selected held task. [ADR 0072](0072-a-held-task-asks-the-person-only-when-its-agent-says-so.md) (proposed) would amend which tasks are held: only those the creating agent says are the person's, and at once those no agent created.

Reason: the runtime already decides when work stops and how it starts again, so a typed view of its state, with the runtime's own resume, gives the person one tap without a second scheduler or guessing from prose. Naming the concept "held task", not after Hermes's kanban, lets another runtime map its own state (OpenClaw's paused subagent, to verify) onto the same card. Restricting resume to the host's person keeps a conversation share from restarting work that other agents depend on.

## Considered options

- **Read the runtime's notification text.** Rejected: the text can arrive late and contradict itself, as above, and changes with every runtime release.
- **A question card with Resume as a choice.** Rejected: a question binds to a native waiter, and a held task has none.
- **A `kanban` capability.** Rejected: it names one runtime's feature, which OpenClaw has already dropped.
