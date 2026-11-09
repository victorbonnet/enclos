---
name: app-questions
description: Use when asking a person for a choice or missing information through the enclos mobile app.
---

# App questions

Use this skill when a decision or missing detail needs the person's answer in the enclos app. Choose routine, low-stakes details yourself.

1. Ask through the native `clarify` tool. Put the question in `question` and short option labels only in `choices`. The app shows tappable rows, an Other text field and Skip; the person can also answer in the conversation composer.
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

Offer at most four choices. Keep detail in the question and labels short so the whole card fits. Other and Skip are app controls; Hermes supplies them. On an older app or runtime, the same tool can show a numbered text question, and the person replies in the composer.

Use policy request tools for sandbox access; answering a question does not change policy. Request a concrete scope through `enclos_request_access` and wait for the person's decision in the policy inbox.

Hermes creates and waits for its own command approval cards. Let the person answer that native approval; a `clarify` answer supplies no command authorization. Session and always choices are Hermes pattern grants, while Enclos sandbox policy stays unchanged.
