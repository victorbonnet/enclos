---
status: accepted
---

# Refuse what cannot be enforced

Narrowed by [0033](0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md) (proposed): a resource limit the backend cannot enforce as written is refused outright, with no acceptance that lets it through.

If a backend is not available on the host (for example, Landlock is missing from the kernel), enclos refuses to create or start sandboxes on it, with no override. If a policy uses a field the backend enforces only partly or not at all, enclos says so and refuses unless the user explicitly accepts it, and the acceptance is recorded in the audit log. `enclos policy test` checks what is enforced by running probes that must fail: protected and sensitive paths, writes outside the home and workspaces, destinations off the allowlist, and the escape routes in [0016](0016-seatbelt-blocks-host-service-delegation.md). A passing probe run covers only the routes probed, and enclos reports it that way.

## Considered options

- **Never allow an override:** would make `[resources]` unusable on macOS, where limits are only partly enforced, even when that is good enough.
- **Warn and run:** the user could not tell a protected sandbox from an unprotected one.
