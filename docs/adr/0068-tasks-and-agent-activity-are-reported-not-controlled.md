---
status: proposed
---

# Tasks and agent activity are reported, not controlled

When one agent hands work to another through its runtime (Hermes's kanban board), the assignee runs it outside every conversation, and the app showed nothing: the person saw the delegating agent go quiet and could not tell whether anyone was working. Hermes runs the task's turn in the assignee's own gateway, where its channel plugin is loaded, but its board's plugin hooks fire in whichever process wrote the board, and several changes (a retry after a crash, giving up, unblocking, archiving) fire none ([source findings](../research/hermes-tasks.md)).

Decision (proposed):

- **A task** is work an agent does outside a conversation's answer, which its runtime tracks from the moment it is asked for until it ends. A runtime-neutral, optional `tasks` channel capability, announced in both the bridge's and the plugin's `hello`, carries the runtime's tasks to the app: `task.update` for one, and `tasks`, the whole list, after each `hello` and whenever the plugin needs to reconcile. States are `queued`, `running`, `blocked`, `done`, `failed` and `cancelled`.
- **Only the assignee's own plugin reports a task**: the bridge refuses one whose `assignee` is not the agent its connection proves. Every field is untrusted text from the sandbox, which the bridge cleans (one line, hidden characters removed) and cuts itself.
- **The bridge keeps tasks, bounded**, so a device that was away gets them at `sync`: at most 100 per sandbox, an ended one for 3 days. Only the host's person sees them, as with policy requests: a task can name repository paths and internal plans.
- **Agent activity** finishes #194 as a list: `agent.activity` says what an agent is doing (`answering` a conversation, a `routine`, a `task`), several at once, an empty list for idle. The bridge holds the current state, gives it to a device when it connects, and makes an agent idle when its plugin's connection closes; the plugin repeats it after each `hello`. Another person than the host's sees only the `answering` entries of their own conversations.
- **Nothing here carries authority.** A task and an activity are reported, like a `tool` step: no control (cancel, retry, unblock) is part of this decision.
- **A held task is a `blocked` one.** [ADR 0066](0066-held-tasks-stay-with-the-runtime.md) (proposed) shows background work that waits for a person as a card the host's person can resume. This decision reports every task, held ones included, and adds no resume: that control stays 0066's, and a runtime can serve both capabilities from the same state.
- **A plugin reads its runtime's state, not its notifications.** Hermes's adapter reads the board read-only and watches its event log, taking hooks only as a cue to read again. A runtime with no such state (OpenClaw 2026.11.2 has no task board) does not announce the capability.

Reason: the runtime already knows who works on what; a typed, reported view of it shows the person that work is going on without a second board in enclos. Requiring the assignee's plugin to report keeps one report per task when agents share a board and stops a plugin from posting another agent's work. Keeping tasks, unlike tool steps, lets a phone that was away see what happened while it was.

## Considered options

- **The delegating agent's plugin reports the task.** Rejected: it is not running the work, Hermes does not tell it reliably when the work changes, and the conversation it would post to may belong to another agent.
- **A live, unkept stream, like `tool`.** Rejected: delegated work runs for minutes or hours, and a phone that was away would never learn how it ended.
- **A `kanban` capability.** Rejected: it names one runtime's feature, which OpenClaw has already dropped.
