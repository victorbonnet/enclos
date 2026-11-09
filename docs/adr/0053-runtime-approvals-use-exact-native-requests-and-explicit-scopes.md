---
status: proposed
---

# Runtime approvals use exact native requests and explicit scopes

Hermes's command guard already waits for Allow once, Allow for session, Always allow or Deny. Typing `/approve` addresses native pending work, while a stale app button must never resolve a later request. Treating a command approval as an ordinary information question would also invent Other/Skip or lose the meaning of persistent consent.

Decision (proposed): extend [0052](0052-questions-keep-their-runtime-waiter-and-structured-app-controls.md)'s durable control transport with explicitly typed runtime-approval metadata and actions, a separate capability and a distinct history kind. The runtime supplies the full redacted display command, reason and permitted scopes. The bridge requires both the current conversation owner and the host's own person on a paired device. Its adapter resolves only the exact native request; it neither sends a chat command nor executes a host shell command. The native guard continues under the unchanged sandbox policy, and retains responsibility for pattern grants and execution. Existing revision, receipt, reconnect and no-automatic-retry rules apply, including Deny.

Android and iOS show the complete literal command and reason with only the offered scope buttons, using each platform's native controls in the app's design tokens. There is no default choice. Deny-only remains deny-only. Session and persistent pattern grants are explained at the decision. An exact receipt confirms the consent action, never execution success. A native decision made elsewhere closes the card without inventing its undisclosed scope or outcome. Android is implemented first; the app's spec and ADR record iOS parity.

Reason: reusing durable delivery avoids a second control queue, while distinct typed actions preserve the authority difference between information, runtime consent and sandbox policy requests ([0046](0046-the-hosts-person-approves-sandbox-policy-scopes-from-the-phone.md)). Feature-detect native exact-request and additive lifecycle APIs; older Hermes, bridges and apps keep readable typed-command fallback. Matching by command text, queue position or session alone cannot make a stale button safe. This is a generic runtime contract; Hermes is its first adapter.

Persisted typed approval answers and the actionless `resolved` state require an approval-aware bridge reader. Rolling back to the preceding binary over those retained records requires a compatible reader or a pre-feature database restore; client text fallback does not make that database downgrade safe.
