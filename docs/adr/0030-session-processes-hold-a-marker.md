---
status: accepted
---

# A session's processes hold a marker enclos can find

[ADR 0019](0019-sandbox-members-and-effective-policy.md) has `stop` signal only processes shown to be members, and left a mechanism that also covers a double fork to experiments in a VM. On macOS, process groups and the parent chain lose a process that double-forks; the prototype refuted `sandbox_check` on another process, and `ps -E` shows no other process's environment on macOS 26, so a token in the environment cannot be read back. The VM run (design §14) showed the gap: a double-forked process was listed but not signalled, and one that also called `setsid` was not seen.

**Decision.** Before it starts a sandboxed program, a session's or a service's, enclos makes a marker file with no permissions in the sandbox's `members/` folder, and the program inherits an open descriptor to it; enclos keeps none. The marker is named after the session's root process (pid and start time) before the session is recorded. A process that `lsof` shows holding a session's marker is a sure member of that session, whatever its group or parent: `show`, `status` and `rm` count it, and `sandbox stop`, and `sandbox start` and `launch` where they end the sessions a service replaces, signal it. This extends [ADR 0019](0019-sandbox-members-and-effective-policy.md), whose rule that only processes shown to be members are signalled it meets within the limits below; once accepted, 0019's macOS consequence points here.

**Why.** An inherited descriptor survives a fork, a double fork and `setsid`. A sandboxed process can neither open a file with no permissions nor change its mode, since a sandbox writes only to its home, and changing a mode is a write ([ADR 0015](0015-broad-reads-narrow-writes.md)), so a holder is the program, a process it started, or a process outside the sandbox that changed the marker's mode or was handed the descriptor. `lsof` needs neither root nor `unsafe` code.

**Consequences.**

- A process that closes its inherited descriptors, as one that detaches itself carefully does, is not proven by its marker; the earlier rules still apply to it, and it keeps its Seatbelt restrictions.
- A process of the user outside any sandbox that changes a marker's mode and opens it, or is handed its descriptor over a socket, counts as a member and is signalled by a stop: no accident does either (ADR 0014).
- Root can open a marker; `lsof` run as the user does not list root's processes, and enclos could not signal them.
- Each look at a session's members that decides what to signal or report (by `stop`, `start`, `launch`, `show`, `status`, `rm`, and when a program exits) runs `lsof`, after `ps`, so a pid reused in between is not taken for a holder; the twice-a-second watch of a running session does not.
- Shown in a VM (design §14): both kinds of double fork were found, listed and ended by `sandbox stop`, which left the sandbox stopped, not failed; a Hermes gateway service held its marker; the host could not open a marker.
