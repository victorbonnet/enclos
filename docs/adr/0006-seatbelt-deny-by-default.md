---
status: proposed
---

# Compiled Seatbelt policies start from deny by default

Compiled Seatbelt policies start from `(deny default)` and allow only what the agent needs, instead of `(allow default)` with deny rules for writes, sensitive reads, the network and host services. A deny-by-default policy cannot leak through an operation nobody thought to deny, and the agent sandbox escapes reported in 2026 targeted allow-by-default Seatbelt configurations. File reads stay broad either way ([0015](0015-broad-reads-narrow-writes.md)); the difference is in Mach services, system calls, IOKit and other operations.

## Before this is accepted

The milestone 2 prototype must produce evidence, not just a working agent. Hermes running its weather task under the policy shows the policy is usable; it does not show it isolates. Acceptance needs:

- the complete list of `mach-lookup`, `sysctl`, `iokit` and other allowances Hermes, its installers and any browser it starts need, short enough to review line by line;
- every escape probe from [0016](0016-seatbelt-blocks-host-service-delegation.md) and the protected-path and network probes failing under it;
- the same probes run against the allow-by-default policy, so the two baselines are compared on evidence.

If the allowance list is too large to review, enclos keeps allow-by-default with explicit deny rules, including the host-service blocks, and this ADR is rejected.
