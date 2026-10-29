---
status: accepted
---

# macOS: Seatbelt is the first backend, despite its deprecation

The first backend is Seatbelt on macOS: enclos compiles the policy into a `.sb` file and runs the agent with `sandbox-exec`. `sandbox-exec` has been marked deprecated since 2016, but it still ships, it is the only native way to sandbox an arbitrary macOS binary without a VM, and major tools rely on it. Its removal is tracked as a risk; the microVM backend (libkrun) is the fallback.

## Consequences

- A compiled Seatbelt policy is fixed for the life of the process. File, program and resource changes need a restart, which enclos asks for; if the user declines, the change stays pending ([0018](0018-immutable-policy-snapshots.md)). Network changes are live because the proxy enforces them.
- Limits are only partly enforced: per process, open files through `ulimit`; a process may ignore SIGXCPU and run past its CPU time, a memory limit cannot be set with `setrlimit`, a file size limit does not hold appends, and enclos has no means for a CPU share, so all four are refused (design §7, [0033](0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md), proposed).
- Delegation to host services must be blocked separately, whatever the baseline ([0016](0016-seatbelt-blocks-host-service-delegation.md)).
