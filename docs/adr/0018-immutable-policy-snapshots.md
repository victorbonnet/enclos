---
status: accepted
---

# Policies are immutable resolved snapshots, with one active and at most one pending

A snapshot is the fully resolved policy together with the inputs it was resolved from (enclos's built-in defaults and version, the template and its content hash, the runtime adapter's contributed endpoints and version, and the sandbox's overrides), identified by the SHA-256 of both. Snapshots are insert-only, and identical content reuses the existing snapshot. A sandbox's history is an append-only list of numbered versions, each pointing to a snapshot. A sandbox has one active snapshot, which every new session uses, and at most one pending snapshot.

- A file, program or resource change applies at once when no session is running. When sessions are running it needs a restart and asks first. If the user declines, it is saved as the pending snapshot, the active one stays in force, and both are shown. New sessions keep using the active snapshot until the pending one is applied. A change that mixes a restart-requiring part with network changes is pending as a whole.
- A network-only change takes effect at once as a new active snapshot; if a change is pending, it is re-resolved into a new pending snapshot that includes the network change.
- An enclos or template update never silently changes grants. At launch, enclos uses the active snapshot as stored; `enclos policy refresh` resolves against the current template and adapter and turns any difference into a change for the user to accept.
- Rollback makes an earlier snapshot the target again, as a new version that records which one it restores, so it brings back the effective policy rather than only old overrides. It follows the same restart rules as any change. A rollback or refresh made while a change is pending replaces it, after asking.

## Considered options

- **Store only the overrides file per version:** small, but the same overrides resolve to different grants after a template or adapter update, so history could not show what a sandbox actually ran with.

## Consequences

- Audit entries and session records reference snapshot hashes, so it is always known which policy a process started under ([0019](0019-sandbox-members-and-effective-policy.md)).
- Rules that enclos itself always adds (protected paths, host-service blocks) belong to the compiler, not to snapshots, and only restrict. Compiled policies are named by the digest of their text, so an upgrade that compiles a snapshot differently writes a new file at the next session start, and stricter enclos-owned rules apply to new sessions without asking; `enclos doctor` lists what changed. An upgrade never loosens these rules this way.
