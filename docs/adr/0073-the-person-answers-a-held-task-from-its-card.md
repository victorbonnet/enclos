---
status: proposed
---

# The person answers a held task from its card

A held task's card under "Needs you" shows the task's title, the runtime's block reason and "Decide on the agent's task board", with **Open task board**, View task, View conversation and Dismiss ([0066](0066-held-tasks-stay-with-the-runtime.md), [0070](0070-paired-devices-open-a-held-tasks-board-through-the-bridge.md)). None of them answers. On the board of #332, every held task was a choice between two named options.

One card read "Existing decision remains unanswered: #346 ordinary chat text can block backup/restore; both independent reviews HOLD and both coding runs …". The agent had already written the question for the person in a comment on the task:
- "Allow one more hour to fix Hermes backups?";
- one sentence on what blocked it;
- "1A: allow one 60-minute correction run (recommended)" and "1B: keep #346 paused".

The card showed none of this. To answer, the person had to:
1. open the board or the task;
2. find that comment;
3. go to the agent's Home;
4. type "1A" with enough context to name the task.

[0072](0072-a-held-task-asks-the-person-only-when-its-agent-says-so.md) makes the agent that created the task say when a hold is the person's, through a tool the plugin gives it. Its card still says to answer in the conversation.

An ordinary [question](0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md) has choices, but it is bound to a runtime call that waits within one turn (Hermes's `clarify`), and its answer never starts a turn. A hold lasts hours, long after the turn that asked about it ended.

Decision (proposed), extending 0072:

- **The agent writes the card.** The tool by which the agent hands a held task to the person takes, all under an ordinary question's text rules and kept with the hold as 0072 keeps the agent's word:
  - **the decision**, one short question ("Allow one more hour to fix Hermes backups?");
  - **what is blocked**, in one or two plain sentences: what stopped and why it needs the person ("Both reviews found that ordinary chat text can stop an agent's backup or restore. The two approved coding runs are used up.");
  - **up to 4 choices**, each one line saying what happens ("Allow one 60-min fix, then review and CI", "Keep #346 paused"), or none for a free answer;
  - **optionally which choice the agent recommends.**

  The plugin's per-turn hint asks for words the person needs, not run numbers, hashes or the runtime's own terms.
- **The card shows what the agent wrote, and the answers first.** Its header names the agent that asks and, when another agent is doing the work, whose task it is ("runtimes · Director's task"). Below that, in order:
  1. the decision;
  2. "Blocked:" with what is blocked;
  3. one button per choice, the recommended one first and marked;
  4. a text field with Send for any other answer.

  Everything else is under a collapsed **Details**: the task's id and title, the runtime's reason, View task, View conversation, **Open task board** and Dismiss reminder. The board is for looking into the task, not for answering.
- **One tap answers.** A button, or Send, is a live, correlated control from the host's person on a still-paired device, fenced by the card's revision, as Resume is. It is never queued or resent, and it is audited.
  - The plugin checks the task is still held at the revision the agent asked about. It then gives that agent a turn in the conversation it asked from: a message from the person naming the task by id and title, the decision, and the chosen label or the typed text. The bridge stores it in that conversation's history as the person's message.
  - Once the plugin confirms, the card shows "Answered: …" and leaves "Needs you". It comes back only if the agent asks again, on a new hold.
- **The agent acts on the answer with its own tools** (Hermes: unblock, comment, specify), as it would on a typed reply. The answer grants nothing the same message typed by the person would not.
- **A card no agent wrote** (a hold no agent will hear of, 0072, or a plugin without the tool) shows the task's title as the decision and the runtime's reason, cut to two lines, as what is blocked. It offers **Ask the agent**, which starts the same kind of turn for the agent whose Home holds the card ("Look into task … and tell me what you need from me"), and Resume where the runtime allows it. It has a text field too.
- An older app or bridge gets the decision, what is blocked and the choices as the card's readable text, and the person answers in the conversation as before.

Reason: the agent that asked for the task knows what is blocked, what each answer means and which it would pick. So it writes the card in the person's words and gets the answer back, rather than the app reading the board or acting on it, which tasks never do ([0068](0068-tasks-and-agent-activity-are-reported-not-controlled.md)). Here one answer gives a coding run and the other leaves the work paused. Starting a turn is what a typed reply does already. The card only removes the reading, the finding and the typing, and records which task and option the person meant.

## Considered options

- **Show the runtime's reason as it is, with buttons parsed from it or from the agent's comments.** Rejected: it guesses from prose, which enclos never does to make a control, and the reason is written for the agents.
- **Ask an ordinary question from the wake turn** (Hermes: `clarify`). Rejected: the question would hold the agent's turn until the runtime's timeout and expire long before the hold ends. Meanwhile it delays a graceful restart of the gateway, which waits on that turn.
- **Let the answer act on the task** (resume it, or post the choice as a comment). Rejected: whether a choice means resume, specify, reassign or close is the agent's to decide, and the board is reported, not controlled.
- **Keep Open task board as the main action.** Rejected: the board answers nothing and opens on a task's details written for the agents.

## Consequences

- The held task report gains optional fields: the decision, what is blocked, the choices and the recommended one. The device and plugin legs gain an answer control with its own capability. The plugin keeps what its agent wrote with 0072's state.
- 0072's card text ("answer in the conversation the agent asked from") gives way to the answer on the card. Its rule on who asks is unchanged.
- 0052's rule that a question's answer never becomes a turn is unchanged: this is a held task's answer, not a question's.
