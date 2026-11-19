---
status: proposed
---

# A held task asks the person only when its agent says so

[ADR 0066](0066-held-tasks-stay-with-the-runtime.md) holds every task the runtime has stopped that an agent created, and each one is an open item under "Needs you". On a board shared by a built-in agent and six specialists (Hermes 0.23.1, #332) that was wrong three ways:

- A worker's question for the agent that assigned its task became the person's. Hermes's `needs_input` block is what a worker uses for any question, and its loop breaker words a repeated one as "needs a human decision" (`_fmt_block_loop_detected`). Its `blocked` event records the kind and the reason, not who blocked.
- A task whose creator Hermes recorded as `user` (its CLI's name when no profile is known, `hermes_cli/kanban.py`) or `dashboard` was reported by no agent, so a held task showed nowhere.
- An item stayed after the person had answered in the conversation, because the agent kept the task in triage on purpose, and its sheet sent the person to "the agent's task board", which opened on 106 cards.

Decision (proposed), amending 0066:

- **A hold goes to the agent first.** When the runtime stops a task an agent created, that agent decides: it answers the worker, resumes the task or ends it itself. Hermes already wakes it with the event. The task is reported as `blocked` (0068) meanwhile, so the person still sees it in the agent's tasks.
- **It is held for the person only once that agent says so.** The plugin gives the agent a tool (for Hermes, one the enclos plugin registers) that names the task and the question for the person. The plugin keeps what the agent said with the hold it answers, the task's revision at that moment. A new hold after the task ran again needs the agent to ask again. The plugin tells the agent of the tool in each turn, as it tells it how the app draws a task (`tasks.WRITING_HINT`).
- **A task no agent created is the person's at once.** When the creator is no agent of the runtime (Hermes: `user`, `dashboard`, or a profile that no longer exists), there is nobody to ask first. The sandbox's built-in agent's plugin (Hermes: `default`) reports it, and so does its assignee's. The bridge keeps one card per task: the built-in agent's when it reports it, else the assignee's. Why Hermes recorded `user` for tasks the built-in agent asked for is to verify, so that an agent's own tasks carry its profile.
- **The item says what and where.** A held task's card names the task by its id and title, gives the agent's question, and says to answer in the conversation the agent asked from. **Open task board** opens on that task. A task held by Hermes's loop breaker keeps no Resume (0066).
- **The item goes when the agent says the person answered**, through the same tool, or when the task leaves its hold, as before. An agent that keeps the task stopped on purpose no longer leaves a stale question.

Reason: the agent that asked for a task knows whether a worker's question is its own to answer. Only it can say the person must act, and the board cannot tell one question from the other. A typed statement from the agent, kept against the hold it answers, makes "Needs you" mean that someone is waiting on the person.

[ADR 0073](0073-the-person-answers-a-held-task-from-its-card.md) (proposed) extends this: the agent asks with choices, and the person answers from the card.

## Considered options

- **Hold every `needs_input` block, as in 0066.** Rejected: a worker's question for its assigning agent reaches the person, worded as theirs.
- **Tell the person's question apart on the board** (the blocking profile, a block kind, a reason's wording). Rejected: Hermes's `blocked` event does not record who blocked, and a worker uses `needs_input` for any question.
- **Let the agent ask in the conversation only, with no card.** Rejected: the question scrolls away, raises no notification after an app restart, and offers no Resume.

## Consequences

- An agent that never uses the tool leaves its stopped tasks out of "Needs you". They still show as `blocked` tasks.
- The plugin keeps a small state of its own (what its agent said, and for which hold), which must survive a gateway restart.
