---
status: proposed
---

# Questions keep their runtime waiter and structured app controls

Hermes's `clarify` can ask for one or several choices, another answer or a skip. A numbered chat message makes the person type a number; inferring controls from markdown cannot distinguish that request from an ordinary list or establish whether its waiter still exists. Other runtimes need the same app behaviour.

Decision (proposed): an optional **questions** capability carries an immutable question definition and typed answers through the conversation protocol. The runtime owns the waiting call. Its channel adapter binds the app question id to that exact native waiter and session. The bridge persists the question's conversation, authenticated origin, current state and revision with its history; only the conversation's owner on a paired device may answer. A live, correlated control resolves the native waiter directly. It never becomes a new chat turn. The first accepted native answer settles the card; terminal state cannot reopen.

The app renders native single/multiple selection, custom text and Skip and waits for the exact answer receipt. It keeps the newest state across cache reads, broadcasts and sync, and sends nothing automatically after disconnect or an ambiguous timeout. Runtime restart expires old cards through reconciliation. Pending state is refreshed on every device sync; terminal changes append a quiet history message. Separate bounded metadata frames accompany readable fallback messages, so older apps can use the runtime's text interceptor (an option's number or text, or "skip"; other prose cancels the question and reaches the agent as a message, as Hermes does for its own cards). An older bridge or runtime keeps native text fallback. Agents use their runtime's existing question tool, guided by a channel hint and bundled skill.

Reason: retaining the native waiter preserves the runtime's tool results, timeout and interruption behaviour. Structured ids and validation bind an answer to one real question, while durable bridge history keeps the app consistent across devices and restarts. The extra state, correlation and replay handling avoid guessing from prose or inventing a second question tool. A question answer changes no sandbox policy and executes no host command; policy requests remain a separate operation.
