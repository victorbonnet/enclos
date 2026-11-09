# M5 OpenClaw verification

This record distinguishes implemented contracts from live acceptance. The stack
starts at [enclos #217](https://github.com/victorbonnet/enclos/pull/217) and
[enclos-app #42](https://github.com/victorbonnet/enclos-app/pull/42).
[Issue #218](https://github.com/victorbonnet/enclos/issues/218) remains open.
Linux live acceptance stays last on the new host; no Pi run is required.

## Agreed capability boundary

M5 ships complete native question text and trusted native credential-request
instructions. It does not advertise structured questions or manufacture a second
question tool. Rich question controls are tracked in
[#225](https://github.com/victorbonnet/enclos/issues/225).

Routines expose native inventory and supported full definitions read-only.
`options.operations=["get"]` hides unavailable controls. Conditional mutations,
complete agent-targeted creation and manual-run authority are tracked in
[#226](https://github.com/victorbonnet/enclos/issues/226). No read/compare followed
by an unconditional scheduler mutation substitutes for native revision checks.

Native approvals negotiate independent offered scopes and preserve OpenClaw's
persistence description. Once/Always/Deny does not invent Session. Structured
cards require the exact native request and current account/conversation/person;
unsupported requests retain native fallback. Consent receipts record native
resolution, not execution success.

## Live macOS evidence, 2026-11-09

The disposable test used Seatbelt, an enclos-managed proxy and launchd services,
OpenClaw **2026.11.2** (`b556fdf`), private Node **24.22.1** and native Codex
**0.164.0**. The official local-prefix installer SHA-256 was
`2218bac9796a5da99f6be8e7cc838420e282aca7897bea80a8f40dab0f6bfc3d`.
Native ChatGPT subscription device login completed inside the disposable state.
No credential values or provider profile files form part of this record.

| Check | Observed result |
| --- | --- |
| Official installation | Production `runtime install openclaw` completed through a recorded confined session, using private runtime/Node paths and no native host service. |
| Native agents | Main/scout were discovered and adopted; a third disposable agent was created and removed through enclos. Native configuration, workspace/session paths and core metadata confirmed deletion. |
| Gateway authentication | Protected JSON file SecretRefs authenticated the managed local Gateway. Its secret value was absent from ordinary settings and service startup environment. |
| Managed lifecycle | Clean stop/restart reported no survivors for the test session; authenticated model use worked after restart. |
| Actual model | Production launcher returned exactly `M5_OK` in 14.23 seconds; native terminal receipt reported zero successful tool calls. |
| macOS certificate roots | Original native model failed with `UnknownIssuer`. The supported public CA bundle restored verified TLS; executable regression failed before the launcher fix and passed after. Explicit CA overrides remain honored. |
| Baseline app channel | Installed OpenClaw loaded the real package. Main/scout `/help` round trips retained reply correlation; a wrong socket token was refused. |

The prototype's earlier, narrower observations remain in
[its evidence record](../prototype/m5/README.md). Those observations do not become
broader claims merely because later implementation exists.

## Repeatable implementation checks

Run `just ci` from the stack tip with Rust and Node 24 or later. It checks the
workspace, dependency policy, Hermes plugin, OpenClaw launchers, emitted entry
point and channel tests. The channel uses only Node's standard library and public
OpenClaw SDK entry points; generated JavaScript ships with the Rust binary.

Native SDK tests additionally require the exact tested package:

```sh
ENCLOS_OPENCLAW_PACKAGE=/path/to/openclaw \
  node --test channels/openclaw/tests/*.test.js
```

Without this variable, native-package tests explicitly skip. Standard transport,
protocol, routing, files and authority tests still run. CI installs the tested
2026.11.2 SDK package in a disposable prefix and runs the native tests too.
Changing the tested runtime version requires updating and re-running the native
contract probes; the runtime installer itself remains official/as served.

## Final stack checks

The combined source passed **1,564 Rust tests**: 1,331 library, 67 CLI-unit,
100 CLI-integration, 24 documentation, 36 protocol and six shared fixtures.
Workspace Clippy, formatting and `cargo deny` passed. Destructive runner-only
host-service/member probes were not enabled on this Mac.

The final OpenClaw suite passed **67 tests with zero skips** against the installed
SDK; six launcher/owner-helper tests also passed. Hermes Python 3.13 verification
ran 103 cases: **70 passed, 33 skipped**, with all six exact-interruption cases
included (three fixtures and three using the pinned real public helper).
Optional unavailable Hermes integrations remain skips rather than proof.

Android companions [#45](https://github.com/victorbonnet/enclos-app/pull/45) and
[#46](https://github.com/victorbonnet/enclos-app/pull/46) passed offline debug APK
builds, 95/96 unit tests and lint with no new warnings, and all remote CI checks.
The FFI encryption boundary transports opaque JSON bytes; no native ABI or
pinned-core update was required for these optional protocol fields.

One Ubuntu 26.04 CI run hit an occupied proxy test port; neighboring stack runs
passed. The newly added encrypted-sync fixture now uses the existing allocator
that excludes proxy ports. The exact occupant was not captured, so this is a
confirmed fixture-invariant correction rather than proof of the collision's
origin. A focused encrypted connection test passed after the change.

## Remaining live acceptance

Use [the operator guide](openclaw.md), the existing [manual test](manual-e2e.md)
and [M5's acceptance gates](m5-openclaw.md#acceptance-gates). Keep every result
attached to its actual tested version and environment.

- [ ] Two independently installed OpenClaw sandboxes, two agents each, alongside
  a functioning Hermes sandbox; separate state, ports and native defaults.
- [ ] Distinct Telegram bots, allowed-person delivery and unlisted-person refusal;
  missing/rotated secret references and no credential disclosure in audit/logs.
- [ ] Paired Android direct/Home/group flows: continuation, names/photos, read
  state, archives, files/static HTML, commands, typing/tool events and titles.
- [ ] Exact cancellation and policy requests on the real phone, including stale
  controls, reconnects, another conversation and a later run.
- [ ] Read-only native routine inventory/details, unsupported schedule handling
  and scheduled delivery while the phone/bridge is away and after restart.
- [ ] Native approval cards, actual offered scopes, two-device races, external
  settlement, expiry/restart and older-peer complete fallback; question text.
- [ ] Dashboard handoff, status/doctor/logs, proxy allow/deny, audit verification
  and restart/reload/member cleanup within documented lifecycle guarantees.
- [ ] New Linux host: real bubblewrap/systemd, secret store, relay/socket/proxy,
  dashboard/auth and configured lingering across logout/reboot. Run dangerous
  escape/member probes only in disposable CI/VMs.

Until these gates pass, report **macOS acceptance incomplete; Linux pending**.
Do not close M5 based on source tests, installation or one successful model call.
