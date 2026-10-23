---
status: accepted
---

# Compiled Seatbelt policies start from deny by default

Compiled Seatbelt policies start from `(deny default)` and allow only what the agent needs, instead of `(allow default)` with deny rules for writes, sensitive reads, the network and host services. A deny-by-default policy cannot leak through an operation nobody thought to deny, and agent sandbox escapes reported in 2026 targeted allow-by-default Seatbelt configurations ([Pillar Security](https://www.pillar.security/blog/escaping-antigravitys-allow-default-seatbelt)). File reads stay broad either way ([0015](0015-broad-reads-narrow-writes.md)); the difference is in Mach services, system calls, IOKit and other operations.

## Before this is accepted

Milestone 2 must produce evidence, not just a working agent. Hermes running its weather task under the policy shows the policy is usable; it does not show it isolates. Acceptance needs:

- the complete list of `mach-lookup`, `sysctl`, `iokit` and other allowances Hermes, its installers and any browser it starts need, short enough to review line by line;
- every escape probe from [0016](0016-seatbelt-blocks-host-service-delegation.md) and the protected-path and network probes failing under it;
- the same probes run against the allow-by-default policy, so the two baselines are compared on evidence.

Decision rule: whichever baseline is chosen must pass every probe; a probe that fails under a baseline is fixed in its rules before the comparison counts. If both pass and the deny-by-default allowance list can be reviewed line by line, this ADR is accepted. If the list is too large to review, enclos keeps allow-by-default with explicit deny rules, including the host-service blocks, and this ADR is rejected. If a probe cannot be made to fail under allow-by-default, this ADR is accepted regardless of the list's size, or the route is recorded as an unresolved gap in the design.

## Evidence and decision (2026-10-22, macOS 26.5.2)

Accepted by the rule above. The allowances are [`deny-default.sb`](../../src/backend/seatbelt/deny-default.sb): process fork and exec, file reads (the deny list after it still takes away what it names), `sysctl` reads, signals and process information for the sandbox's own processes, `ioctl` on what a process has open, pseudo-terminals, seven named Mach services (notifications, logging, user and group records twice, the per-user temporary folder, the network settings, certificate trust) and the notification center's shared memory. Every rule after them is the same as on the earlier baseline. How the evidence was gathered, and its scripts, are in [`prototype/adr-0006/`](../../prototype/adr-0006/README.md).

- The list came from Seatbelt's own denials, read from a bounded `log stream` while each workload ran under `(deny default)`, and from `(allow … (with report))` traces under `(allow default)`. Each allowance is one a workload failed without. The certificate trust daemon, `com.apple.trustd.agent`, is the one Hermes's installer needed: without it, Python's downloads failed with `OSStatus -26276`.
- Hermes's installer, as `enclos runtime install hermes` runs it, completed its 20 steps under both baselines, Node, ripgrep, ffmpeg and `agent-browser` included (85 and 90 s). `hermes --version`, `profile list`, `config get` and `doctor` printed the same under both. `agent add` made an agent under both. The gateway, started by launchd, ran under both, with no error in its log.
- What deny by default refused that the workloads did without: Node's lookups of `DNSConfiguration` and `launchservicesd`, `analyticsd` and an `fsctl` for `codesign`, and Python's `mach-priv-task-port` on itself. None changed a workload's outcome.
- The escape probes read READY under both baselines on this Mac (72 closed, 10 inconclusive, for folders macOS's privacy protection hides outside the sandbox too). The probes that act on the host if a rule fails (LaunchServices, Apple Events, launchd, preferences, launch agents) run under both in CI, where `ENCLOS_HOST_SERVICE_PROBES=1`: `every_escape_probe_fails_in_a_new_sandbox` under `(deny default)` and `every_escape_probe_fails_under_allow_by_default_too` under `(allow default)`.
- Every test of enclos, those that run real Seatbelt sessions, services and probes included, passes with `(deny default)` as the baseline. It needed pseudo-terminals and `ioctl` beyond the workloads above, for a session's own terminal and those it opens.
- Hermes's browser starts under neither: Chrome for Testing cannot create its socket folder under the write rules (§14), so what it needs under `(deny default)` is not listed yet. A model call and the Telegram gateway answering need a login the evidence runs had not; they are to verify too (design §14).

`ENCLOS_SEATBELT_BASELINE=allow-default` compiles the earlier baseline, only so CI can compare the two on the probes; it is not a setting.
