---
name: app-questions
description: Use when asking a person for a choice or missing information, or sending a digest of blocked work with reply buttons, through the enclos mobile app.
---

# App questions

Use this skill when a decision or missing detail needs the person's answer in the enclos app. Choose routine, low-stakes details yourself.

Explain what is blocked, why, and what the person can decide in one or two plain sentences. Offer two or three short actionable choices, recommendation first. Keep internal run IDs, paths, logs and handoff rules in task reports. Example: “Inbox filters reset when you return from an agent. Allow a fix and independent testing?” Choices: “Fix Inbox filters”, “Keep paused”.

For a digest that should end your turn rather than wait, call `suggest_replies` with up to four literal replies, then send the short explanation as your next message in this conversation. Each button sends its exact text as the person's ordinary message on their next turn. The buttons remain until that person sends another message. Use distinct replies that name the decision, such as “Fix Inbox filters”, so an answer cannot be confused with another blocked task.

1. Ask through the native `clarify` tool. Put the question in `question` and short option labels only in `choices`. The app shows tappable rows, an Other text field and Skip. In a one-to-one conversation the person can also reply in the composer with an option's number or text, or "skip"; any other message cancels the question and reaches you as a message. In a group, a message waits for your turn to end, so the person answers on the card.
2. Put your recommendation first. Hermes adds the recommendation label; the person selects their own answer.
3. Put up to five independent questions in one `questions` array. Hermes delivers them sequentially in this channel. Ask dependent questions after the earlier answer arrives.
4. Wait for the actual tool result. Continue from `user_response` only when its status is `answered`. A skipped or unanswered question supplies no decision. For `cancelled`, `timed_out` or `undelivered`, use the result and notice to decide whether to proceed with a safe assumption or explain the missing answer.

Single selection:

```javascript
clarify({"questions":[{"question":"How should I group the report?","choices":["By project","By week"]}]})
```

Multiple selections use `multi_select`:

```javascript
clarify({"questions":[{"question":"Which sections should I include?","choices":["Summary","Costs","Timeline"],"multi_select":true}]})
```

For a free-text question, omit `choices`:

```javascript
clarify({"questions":[{"question":"What name should the report use?"}]})
```

Offer at most four choices. Keep detail in the question and labels short so the whole card fits. Other and Skip are app controls; Hermes supplies them. On an older app or runtime, the same tool can show a numbered text question, and the person replies in the composer. An unanswered live question times out after an hour; continue from the result Hermes returns. Updated apps keep expired information questions read-only in Needs you, with View conversation and Dismiss reminder. Treat expiry as unanswered; when the decision is still needed, ask a fresh question with current context and wait for its actual result.

Use policy request tools for sandbox access; answering a question does not change policy. Request a concrete scope through `enclos_request_access` and wait for the person's decision in the policy inbox.

Hermes creates and waits for its own runtime approval cards. Let the person answer that native approval; a `clarify` answer supplies no command authorization. Session and always choices are Hermes pattern grants, while Enclos sandbox policy stays unchanged.
