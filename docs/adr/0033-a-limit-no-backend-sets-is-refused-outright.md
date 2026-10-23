---
status: proposed
---

# A limit no mechanism of the backend sets is refused outright

[ADR 0009](0009-refuse-what-cannot-be-enforced.md) refuses a field a backend enforces only partly or not at all, unless the user explicitly accepts it, with the acceptance audited; it rejected "never allow an override" because it would make `[resources]` unusable on macOS. Milestone 2's limits show the two cases apart. `open_files`, `file_size` and `cpu_seconds` are enforced in full as what they say, a limit on each process, by the limits macOS keeps per process. A memory limit cannot be set on a macOS process at all (`setrlimit` refuses `RLIMIT_AS`, `RLIMIT_DATA` and `RLIMIT_RSS`, shown on macOS 26.5.2), and enclos has no means to hold one to a share of the CPU.

Decision (proposed): a limit the backend has no mechanism to set, such as `memory` or `cpu` on Seatbelt, is refused when the policy is stored, with no acceptance to override it. Accepting it would store a limit that nothing enforces, which a user reading the policy would take for a limit. The limits the backend enforces as written need no acceptance. ADR 0009's acceptance stays for a field enforced in part, should one come.

Reason: `[resources]` stays usable on macOS through the three limits it enforces, which is what ADR 0009's rejected option feared to lose, and no policy shows a limit that is not there.
