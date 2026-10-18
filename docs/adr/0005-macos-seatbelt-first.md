# macOS: Seatbelt is the first backend, despite its deprecation

The first backend is Seatbelt on macOS: enclos compiles the policy into a `.sb` file and runs the agent with `sandbox-exec`. `sandbox-exec` has been marked deprecated since 2016, but it still ships, it is the only native way to sandbox an arbitrary macOS binary without a VM, and major tools rely on it. Its removal is tracked as a risk; the microVM backend (libkrun) is the fallback.

## Consequences

- A compiled Seatbelt policy is fixed for the life of the process. File, program and resource changes need a restart; network changes are live because the proxy enforces them.
- CPU and memory limits are only partly enforced (`ulimit`, `taskpolicy`).
