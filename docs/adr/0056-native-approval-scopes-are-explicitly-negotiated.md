---
status: proposed
---

# Native approval scopes are explicitly negotiated

Amends [0053](0053-runtime-approvals-use-exact-native-requests-and-explicit-scopes.md)'s Hermes-shaped scope representation. OpenClaw offers Once/Always/Deny without Session; the original validator requires Always to include Session. Removing that validation globally would change existing peers' interpretation, while adding Session would invent native consent.

Decision (proposed): `runtime_approval_scopes` extends `runtime_approvals` through explicit bridge/plugin negotiation. An extended immutable definition includes literal native scope/persistence and fallback descriptions. Its ordered offered actions are independent; all original Deny/Once/smart-denial, exact-request, receipt and authority restrictions remain. Definitions without the extension retain the legacy Always-requires-Session contract. Native descriptions replace assumptions about persistent command patterns, and fallback uses native instructions rather than fabricated slash commands.

Devices advertise support per authenticated connection in optional `auth.capabilities`. Old auth packets declare none and older bridges ignore the field. Extended structured metadata and answers require this device opt-in; every device still gets complete readable history with the full command and native offered actions. Sync observes the same rule as live delivery. Native plugin binding remains separate work; this change does not establish native resolution or execution.

Reason: two independent negotiations protect both older bridges and older phone apps without changing what consent means. Retained independent-scope history/cache records require compatible readers on rollback, because older validators can reject Always without Session; downgrade does not restore or erase data automatically.
