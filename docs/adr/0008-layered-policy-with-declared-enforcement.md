---
status: accepted
---

# Policies are layered TOML, and each backend declares how well it enforces each area

A policy is TOML that extends a template and overrides only what differs (built-in defaults, then the template, then the endpoints the runtime adapter needs, then the sandbox's `policy.toml`), and it is compiled separately for each backend. The resolved result is stored as an immutable snapshot ([0018](0018-immutable-policy-snapshots.md)). Each backend declares, per policy area, whether it is `Enforced`, `Partial` (with a note) or `Unsupported`. Policy fields stay in the format even when one backend cannot fully enforce them, so the same policy file runs on macOS and Linux.

## Considered options

- **Only allow fields every backend fully enforces:** would remove `[resources]` and `[exec]` everywhere, including on Linux where they are enforced, because Seatbelt only partly enforces them.
- **Cedar or Rego:** expressive, but sandboxes are compiled once at start and cannot evaluate a policy per file access, so most of the language would go unused.
