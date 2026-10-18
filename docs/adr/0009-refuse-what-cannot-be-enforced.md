---
status: accepted
---

# Refuse what cannot be enforced

If a backend is not available on the host (for example, Landlock is missing from the kernel), enclos refuses to create or start sandboxes on it, with no override. If a policy uses a field the backend enforces only partly or not at all, enclos says so and refuses unless the user explicitly accepts it, and the acceptance is recorded in the audit log. `enclos policy test` proves what is enforced by running probes that must fail.

## Considered options

- **Never allow an override:** would make `[resources]` unusable on macOS, where limits are only partly enforced, even when that is good enough.
- **Warn and run:** the user could not tell a protected sandbox from an unprotected one.
