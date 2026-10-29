---
status: accepted
---

# Compiled Seatbelt policies start from deny by default

Compiled Seatbelt policies start from `(deny default)` and allow only what the agent needs, instead of `(allow default)` with deny rules for writes, sensitive reads, the network and host services. A deny-by-default policy cannot leak through an operation nobody thought to deny, outside the operations its allowances name broadly (reads, exec and fork, `ioctl`, pseudo-terminals, `sysctl` reads), and agent sandbox escapes reported in 2026 targeted allow-by-default Seatbelt configurations ([Pillar Security](https://www.pillar.security/blog/escaping-antigravitys-allow-default-seatbelt)). File reads stay broad either way ([0015](0015-broad-reads-narrow-writes.md)); the difference is in Mach services, system calls, IOKit and other operations.

## What acceptance needed

Milestone 2 must produce evidence, not just a working agent. Hermes running its weather task under the policy shows the policy is usable; it does not show it isolates. Acceptance needs:

- the complete list of `mach-lookup`, `sysctl`, `iokit` and other allowances Hermes, its installers and any browser it starts need, short enough to review line by line;
- every escape probe from [0016](0016-seatbelt-blocks-host-service-delegation.md) and the protected-path and network probes failing under it;
- the same probes run against the allow-by-default policy, so the two baselines are compared on evidence.

Decision rule: whichever baseline is chosen must pass every probe; a probe that fails under a baseline is fixed in its rules before the comparison counts. If both pass and the deny-by-default allowance list can be reviewed line by line, this ADR is accepted. If the list is too large to review, enclos keeps allow-by-default with explicit deny rules, including the host-service blocks, and this ADR is rejected. If a probe cannot be made to fail under allow-by-default, this ADR is accepted regardless of the list's size, or the route is recorded as an unresolved gap in the design.

## Decision (2026-10-22)

Accepted, with one condition deferred. The allowances are [`deny-default.sb`](../../src/backend/seatbelt/deny-default.sb), nine rules: fork and exec, reads, `sysctl` reads, the sandbox's own process information, `ioctl`, pseudo-terminals, six named Mach services and the notification center's shared memory (the notification center and `diagnosticd`, also looked up, were dropped once no workload failed without them: through the first a sandbox posts notifications host processes see). Each is one a workload or enclos's tests needed or looked up; the README says which failed without it. The rules after them are unchanged, so signals stay within the sandbox and `TIOCSTI` stays refused. On macOS 26.5.2, Hermes's installer, its commands, `agent add` and its gateway (its `(allow default)` run on an earlier build, as the README says) ran the same under both baselines, the escape probes read READY under both, and every test of enclos passes on the new baseline. The probes that act on the host if a rule fails run under both in CI ([`prototype/adr-0006/`](../../prototype/adr-0006/README.md) has the method, the results and the CI runs).

The browser condition is deferred: Hermes's browser, Chrome for Testing, starts under neither baseline. Under `(allow default)` the write rules keep it from creating its folders (design §5, system temp); under `(deny default)` it exits before it starts, and which denial stops it first is not recorded. So its allowances cannot be listed yet. The rule above decides again once it starts: if its needs under `(deny default)` are too large to review, a new ADR decides whether to supersede this one (design §14).

`ENCLOS_SEATBELT_BASELINE=allow-default` compiles the earlier baseline, only so tests can compare the two: only a debug build takes it (as `cargo build` and `cargo test` make), never a release; any other value but `deny-default` is an error; a program run under it says so on stderr, and `policy test` in its report; the service manager's job file never carries it; and `enclos launch` refuses to start a service while anything but `deny-default` is asked for.
