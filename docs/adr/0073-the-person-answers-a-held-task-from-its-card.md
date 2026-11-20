---
status: proposed
---

# The person answers a held task from its card

A held task's card under "Needs you" shows the runtime's block reason, written for agents, and "Decide on the agent's task board"; none of its buttons answers ([0066](0066-held-tasks-stay-with-the-runtime.md), [0070](0070-paired-devices-open-a-held-tasks-board-through-the-bridge.md)). On the board of #332 every held task was a choice between two options that the agent had already written in a task comment, so the person had to find that comment, open the agent's Home and type the option out. [0072](0072-a-held-task-asks-the-person-only-when-its-agent-says-so.md) makes the agent that created a task say when a hold is the person's, through a tool the plugin gives it.

Decision (proposed), extending 0072: that tool takes what the card shows first. It takes the decision as one question, what is blocked in plain words, up to four choices that each say what happens, and the one the agent recommends. The card leads with these, so the person can decide from it alone: the choices as one-tap buttons, a folded text field for another answer, and the task's reason and board under a collapsed Details. A card no agent wrote offers "Ask the agent for choices" instead. A tap or Send is a live control of the host's person, checked against the card's revision and audited as a resume is. The bridge then sends it to the agent as the person's own message in its Home, naming the task, and the card waits on the agent ("Answered: …") until it asks again or the task is held anew. The agent acts on the answer with its own tools. The wire contract is in `docs/protocol.md`, Held tasks.

Reason: the agent knows what is blocked, what each answer means and which it would pick, so it writes the card and gets the answer back; the app neither reads the answer into the board's prose nor acts on the board itself ([0068](0068-tasks-and-agent-activity-are-reported-not-controlled.md)). Sending the answer as the person's message reuses what a typed reply does, and grants nothing more.

## Considered options

- **Buttons parsed from the reason or the agent's comments.** Rejected: guessing from prose, which enclos never does to make a control.
- **An ordinary question ([0052](0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md), Hermes's `clarify`) from the wake turn.** Rejected: it holds the agent's turn until the runtime's timeout, expires long before the hold ends, and delays a graceful gateway restart, which waits on that turn.
- **The answer acting on the task (resume it, or comment).** Rejected: whether a choice means resume, specify, reassign or close is the agent's to decide.
