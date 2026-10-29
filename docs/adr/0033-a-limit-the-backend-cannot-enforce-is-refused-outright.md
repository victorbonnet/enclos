---
status: proposed
---

# A limit the backend cannot enforce as written is refused outright

Amended by [0038](0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md) (proposed): on a host whose memory cgroup controller is missing or not delegated, bubblewrap accepts `memory` with the user's audited acceptance, and runs with it not applied.

[ADR 0009](0009-refuse-what-cannot-be-enforced.md) refuses a field a backend enforces only partly or not at all, unless the user explicitly accepts it, with the acceptance audited; it rejected "never allow an override" because it would make `[resources]` unusable on macOS. Milestone 2's limits fall on both sides. `open_files` is enforced in full as what it says, a limit on each process, by the limits macOS keeps per process. `cpu_seconds` is not: at the limit macOS sends SIGXCPU, which a process may ignore and then run on. A memory limit cannot be set with `setrlimit` (it refuses `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS`), and a file size limit holds a process's writes but not its appends (macOS checks it against the start of a file opened to append, so each new process may append past it), all three shown on macOS 26.5.2. enclos has no means to hold a sandbox to a share of the CPU.

Decision (proposed): a limit the backend cannot enforce as written, such as `cpu_seconds`, `memory`, `file_size` or `cpu` on Seatbelt, is refused when the policy is stored, with no acceptance to override it. Accepting it would store a limit that does not hold, which a user reading the policy would take for one that does. The limits the backend enforces as written need no acceptance. This narrows ADR 0009's acceptance for `[resources]`, which stays for other areas, and with it [ADR 0008](0008-layered-policy-with-declared-enforcement.md)'s promise that the same policy file runs on every backend: one that sets `cpu_seconds`, `memory`, `file_size` or `cpu` does not run on Seatbelt, and leaves them out there.

Reason: `[resources]` stays usable on macOS through the limit it enforces, which is what ADR 0009's rejected option feared to lose, and no policy shows a limit that is not there.
