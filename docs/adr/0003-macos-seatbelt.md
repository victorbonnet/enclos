# macOS: Seatbelt despite its deprecation

On macOS, enclos runs the command under Seatbelt (`sandbox-exec`) with a deny-by-default profile generated from the policy. `sandbox-exec` has been marked deprecated since macOS 10.12 (2016), but it is still the only native, unprivileged way to sandbox an arbitrary macOS binary, and other agent sandboxes rely on it.

## Considered options

- **Lightweight VM (Virtualization framework):** strongest isolation, but the guest is Linux, startup is slower, and the agent can no longer use the user's macOS tools.

## Consequences

- If Apple removes `sandbox-exec`, enclos on macOS has to move to a VM or to whatever replaces it.
- Profiles start from `(deny default)`. Agent sandbox escapes reported in 2026 targeted allow-by-default profiles.
