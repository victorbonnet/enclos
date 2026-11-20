---
status: proposed
---

# A held task asks the person only when its agent says so

[ADR 0066](0066-held-tasks-stay-with-the-runtime.md) holds every task the runtime has stopped that an agent created, and each one is an open item under "Needs you". On a board shared by a built-in agent and six other agents (Hermes 0.23.1, #332; source checked on 0.23.2) that was wrong three ways:

- A question from a task's assignee (Hermes's worker) for the agent that assigned the task became the person's. `needs_input`, which Hermes's block tool describes as needing "a human decision/answer", is its only block kind for a question, so an assignee uses it for one meant for its assigning agent too; Hermes also records a dependency block with no open parent as `needs_input`. When a repeated one trips the loop breaker, the gateway's ping calls it "needs a human decision" (`gateway/kanban_watchers_notifier.py`, `_fmt_block_loop_detected`). Hermes's `blocked` event records the kind and the reason, not who blocked.
- A task whose creator Hermes recorded as `user` (its CLI's name when no profile is known, `hermes_cli/kanban.py`) or `dashboard` was reported by no agent, so a held task showed nowhere.
- An item stayed after the person had answered in the conversation, because the agent kept the task in triage on purpose, and its sheet sent the person to "the agent's task board", which opened on 106 cards.

Decision (proposed), amending 0066:

- **A hold goes to the agent first.** When the runtime stops a task an agent created, whether for a question, a block, or retries that ran out (Hermes's `gave_up`), that agent decides: it answers the assignee, resumes the task or ends it itself. Hermes wakes it with the event when it asked for the task from a conversation (its `notify+wake` subscription). Meanwhile the task stays among its assignee's tasks (0068): `blocked`, or `queued` once Hermes's loop breaker has moved it to triage.
- **It is held for the person only once that agent says so.** The plugin gives the agent a tool (for Hermes, one the enclos plugin registers) that names the task and the question for the person. The plugin keeps what the agent said with the hold it answers, the task's revision at that moment. A new hold after the task ran again needs the agent to ask again. The plugin tells the agent of the tool in each turn, as it tells it how the app draws a task (`tasks.WRITING_HINT`). Until the agent asks, a task whose retries ran out offers no Resume under "Needs you".
- **A hold no agent will hear of is the person's at once.** That is a task no agent of the runtime created (Hermes: `user`, `dashboard`, or a profile that no longer exists), or one whose creator has no subscription that wakes it for the task (asked for outside a conversation, by a routine or during another task's run). Its card goes to the Home of the sandbox's built-in agent (Hermes: `default`) when that agent uses the app, else to its assignee's: both plugins report it, and the bridge keeps the built-in agent's card when there is one. Why Hermes recorded `user` for tasks the built-in agent asked for is to verify, so that an agent's own tasks carry its profile.
- **The item says what and where.** A held task's card names the task by its id and title, gives the agent's question, and says to answer in the conversation the agent asked from. A task held by Hermes's loop breaker keeps no Resume (0066). **Open task board** already opens on the held task ([0070](0070-paired-devices-open-a-held-tasks-board-through-the-bridge.md)).
- **The item goes when the agent says the person answered**, through the same tool, or when the task leaves its hold, as before. An agent that keeps the task stopped on purpose no longer leaves a stale question.

Built so far, in the Hermes plugin: the tool, its per-turn hint, and the hold going to the agent first, so a held task whose board has a subscription that wakes its creating agent's profile is reported only once that agent asks, and every other hold of a task the agent created at once. Not built: sending the holds no agent will hear of to the built-in agent's Home (or the assignee's); those of a task an agent created still go to that agent's Home, and those of a task no agent created to none. That the agent then acts on the hold is to verify on a running gateway (`docs/design.md` §14).

Reason: the agent that asked for a task knows whether its assignee's question is its own to answer. Only it can say the person must act, and the board cannot tell one question from the other. A typed statement from the agent, kept against the hold it answers, makes "Needs you" mean that someone is waiting on the person. A hold that no agent is told of goes to the person, so none is lost.

[ADR 0073](0073-the-person-answers-a-held-task-from-its-card.md) (proposed) extends this: the agent writes the card for the person (the decision, what is blocked, up to four choices) and the person answers on it.

## Considered options

- **Hold every `needs_input` block, as in 0066.** Rejected: an assignee's question for its assigning agent reaches the person, worded as theirs.
- **Tell the person's question apart on the board** (the blocking profile, a block kind, a reason's wording). Rejected: Hermes's `blocked` event does not record who blocked, and `needs_input` is its only kind for a question.
- **Let the agent ask in the conversation only, with no card.** Rejected: the question scrolls away, raises no notification after an app restart, and offers no Resume.
- **Keep Resume under "Needs you" for a task whose retries ran out.** Rejected: the agent may know why it failed and fix it or end it, and the person resuming blind would spend the retries again.

## Consequences

- An agent that never uses the tool leaves its stopped tasks out of "Needs you". They still show among their assignees' tasks.
- The plugin keeps a small state of its own (what its agent said, and for which hold), which must survive a gateway restart.
