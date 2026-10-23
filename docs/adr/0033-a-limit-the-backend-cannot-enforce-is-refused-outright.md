---
status: proposed
---

# A limit the backend cannot enforce as written is refused outright

[ADR 0009](0009-refuse-what-cannot-be-enforced.md) refuses a field a backend enforces only partly or not at all, unless the user explicitly accepts it, with the acceptance audited; it rejected "never allow an override" because it would make `[resources]` unusable on macOS. Milestone 2's limits show the cases apart. `open_files` and `cpu_seconds` are enforced in full as what they say, a limit on each process, by the limits macOS keeps per process. A memory limit cannot be set on a macOS process at all (`setrlimit` refuses `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS`), a file size limit holds a process's writes but not its appends (macOS checks it against the start of a file opened to append, so each new process may append past it), both shown on macOS 26.5.2, and enclos has no means to hold a process to a share of the CPU.

Decision (proposed): a limit the backend cannot enforce as written, such as `memory`, `file_size` or `cpu` on Seatbelt, is refused when the policy is stored, with no acceptance to override it. Accepting it would store a limit that does not hold, which a user reading the policy would take for one that does. The limits the backend enforces as written need no acceptance. This narrows ADR 0009's acceptance for `[resources]`, which stays for other areas, and with it [ADR 0008](0008-layered-policy-with-declared-enforcement.md)'s promise that the same policy file runs on every backend: one that sets `memory`, `file_size` or `cpu` does not run on Seatbelt, and leaves them out there.

Reason: `[resources]` stays usable on macOS through the two limits it enforces, which is what ADR 0009's rejected option feared to lose, and no policy shows a limit that is not there.
