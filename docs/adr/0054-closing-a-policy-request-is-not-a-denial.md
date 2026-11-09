---
status: proposed
---

# Closing a policy request is not a denial

A person may want a sandbox policy request out of the inbox without accepting or rejecting its scope, especially when approval is unavailable. Hiding it on one phone would let sync or another device bring it back; treating dismissal as Deny would invent a decision.

Decision (proposed): add a host-owned terminal `closed` outcome to [0046](0046-the-hosts-person-approves-sandbox-policy-scopes-from-the-phone.md)'s request lifecycle, separate from policy decisions. Only the host's own person on a still-paired device may close pending or failed requests. Close and approval claim the stored state atomically; an applying request cannot be closed. Closure persists across devices and restarts, with an `approval.closed` audit entry, and the same active policy and scope do not recreate it. A later policy snapshot may produce a new request.

Closing neither changes policy nor replays or resumes an action. It does not roll back failed policy work, change completed approvals or denials, or settle a native runtime approval waiter ([0053](0053-runtime-approvals-use-exact-native-requests-and-explicit-scopes.md)). Android and future iOS expose a neutral **Close request**, feature-detect `approval.close`, and remove the request only after the host reports `closed`; the [protocol](../protocol.md#sandbox-policy-requests) and app spec define the details.

Reason: keeping dismissal in the host's request lifecycle makes it durable everywhere while preserving the meaning and authority of approval and denial.
