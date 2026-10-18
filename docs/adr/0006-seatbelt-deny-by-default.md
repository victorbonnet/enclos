---
status: proposed
---

# Compiled Seatbelt policies start from deny by default

Compiled Seatbelt policies start from `(deny default)` and allow only what the agent needs, instead of `(allow default)` with deny rules for writes, sensitive reads, the network and host services. A deny-by-default policy cannot leak through an operation nobody thought to deny, and agent sandbox escapes reported in 2026 targeted allow-by-default Seatbelt configurations ([Pillar Security](https://www.pillar.security/blog/escaping-antigravitys-allow-default-seatbelt)). File reads stay broad either way ([0015](0015-broad-reads-narrow-writes.md)); the difference is in Mach services, system calls, IOKit and other operations.

## Before this is accepted

The milestone 2 prototype must produce evidence, not just a working agent. Hermes running its weather task under the policy shows the policy is usable; it does not show it isolates. Acceptance needs:

- the complete list of `mach-lookup`, `sysctl`, `iokit` and other allowances Hermes, its installers and any browser it starts need, short enough to review line by line;
- every escape probe from [0016](0016-seatbelt-blocks-host-service-delegation.md) and the protected-path and network probes failing under it;
- the same probes run against the allow-by-default policy, so the two baselines are compared on evidence.

Decision rule: whichever baseline is chosen must pass every probe; a probe that fails under a baseline is fixed in its rules before the comparison counts. If both pass and the deny-by-default allowance list can be reviewed line by line, this ADR is accepted. If the list is too large to review, enclos keeps allow-by-default with explicit deny rules, including the host-service blocks, and this ADR is rejected. If a probe cannot be made to fail under allow-by-default, this ADR is accepted regardless of the list's size, or the route is recorded as an unresolved gap in the design.
