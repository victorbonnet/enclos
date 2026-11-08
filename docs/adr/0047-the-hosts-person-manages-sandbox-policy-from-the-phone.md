---
status: proposed
---

# The host's person manages sandbox policy from the phone

Extends the exact-scope approval surface in [0046](0046-the-hosts-person-approves-sandbox-policy-scopes-from-the-phone.md) and amends the remote-control non-goal for the host owner's paired phone. The sandbox page needs to show accepted access and let its owner remove it or override inherited defaults later.

Only the transport-identified host owner on a still-paired device may inspect or edit policy. The phone proposes one typed field change, never a command or a policy file. The host previews its exact resolved differences and restart requirement; apply revalidates that preview under the state lock against the snapshot, file and running-session state. Edits affect one sandbox, preserve normal host validation, keep built-in sensitive read denials locked, and leave secret-grant management on the host. Inherited values can be overridden without changing a shared template. Saving is audited, updates owner devices and supplies every agent the active policy context; interruption never queues a replay.

This grants existing owner devices policy-editing authority, so revocation is unpairing the device. A separate admin enrollment would narrow authority further, but would split this owner's approval and later-removal flows; shared users and agent plugins receive no such authority. Full policy-file editing is rejected here because a typed single-field edit can be checked and explained before it is applied.
