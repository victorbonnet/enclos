---
status: proposed
---

# The person answers a held task from its card

A held task's card offers Resume, View task, the board and the conversation ([0066](0066-held-tasks-stay-with-the-runtime.md), [0070](0070-paired-devices-open-a-held-tasks-board-through-the-bridge.md)), but no way to answer it. On the board of #332 every held task was a choice between two named options, written only in the block's reason: "authorize a narrow safe-phase test correction or explicitly accept this residual", or whether a run that crashed counts against a one-run allowance. To answer, the person read the reason, opened the agent's Home, and typed a message naming the task and the option. Under [0072](0072-a-held-task-asks-the-person-only-when-its-agent-says-so.md) a held task reaches the person only when its agent says so, through a tool the plugin gives it, and the card says to answer in the conversation, so this stays a typed reply.

An ordinary [question](0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md) has choices, but it is bound to a runtime call that waits within one turn (Hermes's `clarify`), and its answer never starts a turn. A hold lasts hours, long after the turn that asked about it ended.

Decision (proposed), extending 0072:

- **The agent asks with choices.** The tool by which the agent hands a held task to the person takes a question: its text, up to 4 choices (ordered one-line labels, each an action and what follows from it, under an ordinary question's text rules), or none for a free answer, and optionally which one the agent recommends. The plugin sends it with the task in its report, kept against the hold it is about, as 0072 keeps the agent's word.
- **The card shows them as buttons**, the recommended one first and marked, with **Something else** for a typed answer and View task. Tapping one sends the answer. There is nothing to type and no conversation to find.
- **The answer starts the agent's turn.** It is a live, correlated control from the host's person on a still-paired device, fenced by the card's revision, as Resume is. It is never queued or resent, and it is audited. The plugin checks the task is still held at the revision the agent asked about, then gives the agent a turn in the conversation it asked from. The turn is a message from the person, naming the task by id and title, the question and the chosen label or the typed text. The bridge stores it in that conversation's history as the person's message. The card leaves "Needs you" with "Answered: …" once the plugin confirms. It comes back only if the agent asks again, on a new hold.
- **The agent acts on it with its own tools** (Hermes: unblock, comment, specify), as it would on a typed reply. The answer grants nothing that the same message typed by the person would not.
- **A task no agent created** (0072: held for the person at once) has no question. Its card offers **Ask the agent**, which starts the same kind of turn for the agent that reports it ("Look into task … and tell me what you need from me"), besides Resume where the runtime allows it.
- An older app or bridge shows the question and its choices in the card's readable text, and the person answers in the conversation as before.

Reason: the agent that asked for the task knows what each answer means. Here, one answer gives a coding run and the other closes the task with a known gap. So the app returns the person's choice to it, rather than acting on the board itself, which tasks never let it do ([0068](0068-tasks-and-agent-activity-are-reported-not-controlled.md)). Starting a turn is what a typed reply does already. The control only removes the reading, the finding and the typing, and records which task and option the person meant.

## Considered options

- **Ask an ordinary question from the wake turn** (Hermes: `clarify`). Rejected: the question would hold the agent's turn until the runtime's timeout and expire long before the hold ends.
- **Read choices from the reason's text.** Rejected: it guesses from prose, which enclos never does to make a control.
- **Let the answer act on the task** (resume it, or post the choice as a comment). Rejected: whether a choice means resume, specify, reassign or close is the agent's to decide, and the board is reported, not controlled.

## Consequences

- The held task report gains an optional question, and the device and plugin legs gain an answer control with its own capability. The plugin keeps the question with 0072's state.
- 0052's rule that a question's answer never becomes a turn is unchanged: this is a held task's answer, not a question's.
- The plugin tells the agent of the tool's choices each turn, alongside the tool itself, so it asks "Allow one test-only fix" and "Accept lower coverage", not "please decide".
