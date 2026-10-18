---
status: accepted
---

# Policies are immutable resolved snapshots, with one active and at most one pending

Every policy version is stored as an immutable snapshot of the fully resolved policy, identified by the hash of its content, together with the inputs it was resolved from: enclos's built-in defaults and version, the template and its content hash, the agent adapter's contributed endpoints and version, and the sandbox's overrides. A sandbox has one active snapshot, which every new session uses, and at most one pending snapshot.

- A change that needs a restart asks first. If the user declines, it is saved as the pending snapshot, the active one stays in force, and both are shown. New sessions keep using the active snapshot until the pending one is applied. A change that mixes a restart-requiring part with network changes is pending as a whole.
- A network-only change takes effect at once as a new active snapshot; if a change is pending, it is re-resolved into a new pending snapshot that includes the network change.
- An enclos or template update never silently changes grants. At launch, enclos uses the active snapshot as stored; `enclos policy refresh` resolves against the current template and adapter and turns any difference into a change for the user to accept.
- Rollback makes an earlier snapshot the target again, as a new version that records which one it restores, so it brings back the effective policy rather than only old overrides. It follows the same restart rules as any change.

## Considered options

- **Store only the overrides file per version:** small, but the same overrides resolve to different grants after a template or adapter update, so history could not show what a sandbox actually ran with.

## Consequences

- Audit entries and session records reference snapshot hashes, so it is always known which policy a process started under ([0019](0019-sandbox-members-and-effective-policy.md)).
- Rules that enclos itself always adds (protected paths, host-service blocks) belong to the compiler, not to snapshots, and only restrict; whether such changes apply on upgrade without asking is an open decision.
