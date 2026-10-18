# Policies are TOML, deny by default, and only express what can be enforced

A policy is a TOML file listing what a session may do: readable and writable paths, allowed domains, and environment variables passed through. Anything not listed is denied. The schema only contains rules that Landlock, Seatbelt and the proxy can actually enforce, so a policy can never contain a rule that is silently ignored.

## Considered options

- **Cedar or Rego (OPA):** expressive policy languages, but kernel sandboxes cannot evaluate a policy per request for file access. Most of their power would go unused, or produce rules that look enforced but are not.
