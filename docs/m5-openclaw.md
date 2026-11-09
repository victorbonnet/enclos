# M5: OpenClaw alongside Hermes

Milestone 5 adds OpenClaw as a second runtime through the same CLI and mobile app. [Issue #218](https://github.com/victorbonnet/enclos/issues/218) holds the PR checklist. This document records the intended interfaces and acceptance gates; it does not claim that installation, confinement or native capabilities have been demonstrated. [The source findings](research/m5-openclaw-runtime.md) distinguish upstream evidence from required probes.

The stack is rebased onto the requested mobile PR heads: [enclos #227](https://github.com/victorbonnet/enclos/pull/227), `753fc70084b1233c44632979d616148f1b8eda68`, and [enclos-app #44](https://github.com/victorbonnet/enclos-app/pull/44), `4e53b966253e5e3e0348ceed28cb0858c28b0659`, These bases include policy-request closure and the newer core; existing Linux behavior is retained while live OpenClaw Linux acceptance stays deferred. Each M5 PR builds on its predecessor.

macOS implementation and a disposable Seatbelt prototype come first on this host. Linux-specific implementation and live acceptance wait until the new Linux host is ready, as the final PR. Existing cross-platform CI continues, but cannot establish live OpenClaw acceptance. No Pi run is required. Host-service forwards, other runtimes/backends, a general web UI, sharing, iOS and general mobile administration ([#166](https://github.com/victorbonnet/enclos/issues/166)) remain separate work.

## Runtime contracts

These are proposed changes at existing seams, driven by the two runtimes. The implemented trait remains in [`src/runtime/mod.rs`](../src/runtime/mod.rs). Do not describe a proposed method or capability as available before its implementation and tests land.

| Seam | Interface and ownership | Required invariants |
| --- | --- | --- |
| Runtime adapter | Describes native install/mutation commands, agent identities, observations, settings, secret consumers and supervised services. | Every command enclos runs is a `SandboxCommand` executed by the engine in a recorded sandbox session. Login/talk instructions are shown, not run by enclos. Runtime-native parsing and routing stay in the adapter. |
| Engine | Owns state, lock, audit, policy, secret-store access, protected I/O and process identity. | Reads of sandbox data are bounded and do not follow links. Preserve unknown, missing, unreadable and unsupported outcomes. No secret values in arguments, audit, ordinary settings or service startup environments. |
| Channel plugin | Translates native accounts/agents, conversation context, events and native controls into enclos's protocol. | Runs inside the sandbox. The bridge dials an authenticated Unix socket per agent. Stable native context per enclos conversation; persist outgoing ids until acknowledgement and reconcile ambiguous delivery. |
| Bridge and app | Keep people/devices, authority, history, Home, read state, names/photos, archives, groups and push. | No native runtime storage parsing, second scheduler or broad gateway administration exposed to the phone. Capabilities describe installed, tested behavior. |

Keep the interface small by concentrating native knowledge in the adapter and plugin. Shared callers learn normalized results and supported operations; they do not learn Hermes YAML, OpenClaw JSON5, native session keys or native account bindings.

### Identity and observations

A permanent built-in agent and the runtime's selected default target are different facts. Hermes always has `default`; OpenClaw's `main` is removable and another configured agent can be selected. An omitted target must resolve through the installed runtime's state, never a shared literal `default` or `main`.

M5-03 implements `default_agent(home)` and adapter-owned `fact_value(at, text)` interpretation. The engine keeps bounded, link-safe reads and terminal escaping. `ValueAt.keys` are dynamic opaque selectors interpreted by the adapter, so a per-agent selector in shared configuration does not expose that configuration's schema to the engine. Hermes's YAML decoder remains with its adapter.

The engine supplies bounded, link-safe reads from the sandbox home and the adapter interprets the bytes into agent discovery, status and settings findings. Shared JSON/JSON5 configuration must not put OpenClaw's schema in the engine. A configured path outside the readable home, a link or an unsupported include is a finding, not permission to follow it. Directory or database presence does not establish usable authentication. Creation/removal failures may follow partial native work, so reconcile the native roster before retrying or recording success.

### Configuration and secrets

Plain settings are independent of optional secret delivery. The adapter describes native secret references, account-to-agent routing and consumer format; the engine retains atomic protected-file writes, permissions, cleanup and redaction. Hermes's dotenv readers and `${VAR}` references cannot be the universal format. The source-backed OpenClaw candidate is a protected JSON/single-value file read through native SecretRefs, still to probe under Seatbelt. Runtime-owned OAuth remains inside the sandbox.

Per-agent secrets provide routing within a sandbox, not isolation between its agents. Configure allowed people and account bindings before enabling a bot. Refuse unsupported secret values or consumer formats before mutation; never fall back to service startup environment secrets on macOS. Detect plaintext native tokens using the runtime's actual settings format.

### Services, listeners and dashboard

The adapter declares foreground execution, settings reload/restart behavior, listener selection and dashboard access. The prototype must establish one lifecycle owner, including OpenClaw's external-supervisor restart handoff and native hot reload. Do not copy Hermes's USR1 signal: OpenClaw uses it for Node's inspector.

OpenClaw rejects port 0. A configured port is only a candidate: retain process identity, proven member ownership, exclusive listener ownership, loopback-family and proxy-range checks. No all-loopback grant or sandbox-written port file alone establishes a trusted listener. Keep Hermes's existing ephemeral selection. Authenticated readiness is distinct from a listening TCP port. Preserve runtime dashboard authentication and keep one-use privileged browser URLs out of logs and persisted status.

ADR 0028 currently selects a root-process ephemeral listener; a production change to that consequence must explicitly amend or supersede it. ADR 0031's restart ownership must likewise be reconciled with native hot reload, rather than silently adding another owner. Existing ADR statuses are unchanged by this plan.

## Parity and native gaps

All OpenClaw outcomes below await implementation/probes. The matrix is a target, not a capability advertisement.

| Area | Target | Native gap or verification gate |
| --- | --- | --- |
| Installation and setup | Runtime/toolchain/state/cache isolated per sandbox; native login; installer provenance and proxy logs. | Use the official local-prefix runtime-only installer through recorded sandbox sessions. Protect host OpenClaw state first. Verify every download and write; no global install or upstream host service. |
| Agents and observations | List/create/adopt/remove, correct default target, status/doctor/disk facts. | Separate removable default from permanent built-in identity; handle shared JSON5 and partial failures. |
| Import/export | Runtime-native operation under ADR 0026. | OpenClaw's experimental Claws are portable setup, not a per-agent/history export. Initially `agent add --from` is unsupported before staging/mutation; no host extraction or enclos archive. |
| Service and Telegram | Supervision, restart/reload, dashboard and distinct bots routed to agents. | Prove configured listener ownership, external restart handoff, protected SecretRefs, allowed people and per-account bindings. |
| App delivery | Authenticated socket per agent, stable direct/Home/group context, unsolicited output, durable acknowledgement/replay. | Use one runtime plugin package with per-agent accounts, not Hermes's per-profile plugin layout. Avoid default-DM context collapse. |
| Content and events | Markdown, typing, titles/rename, tools, native commands, files and static HTML artefacts. | Verify event attribution and bounded media. No new runtime URL or web control plane exposed to the phone. Reserved stream/abort enum values do not establish a wire implementation. |
| Bridge-owned behavior | Names/photos, read state, Home and archives/groups through existing interfaces. | No runtime-specific implementation of metadata. Groups stay within one sandbox and each agent keeps separate native context. |
| Cancellation | Explicit optional interruption of the exact conversation/turn. | Translate native cancellation inside the plugin; remove the bridge's universal `/stop` assumption. Unsupported interruption finishes and drops the reply, as ADR 0045 already allows. Never stop later/different work. |
| Sandbox policy | Active context, explicit access requests and observed native permission failures. | Reuse bridge authority and exact-scope approvals. No inference from shell strings; native runtime approvals remain separate. |
| Routines | Runtime-owned schedules and delivery; safe live controls and preserved native fields. | Native update has definition-revision CAS, while remove/run lack equivalent checks. A read-compare-unconditional mutation is not atomic. Express support per operation, hide/disable unavailable controls and retain safe updates. Unknown fields/external destinations remain unchanged or read-only. |
| Questions | Exact native waiter, conversation, answer receipt, lifecycle and reconnect reconciliation. | Native batches/forms exceed M4's single ordinary question. Fulfill the whole answer contract or use native fallback/an explicitly negotiated extension; never truncate or answer the next waiter. |
| Runtime approvals | Exact request, complete display command and only native offered scopes. | OpenClaw has Once/Always/Deny, no Session. M4 requires Always with Session. Negotiate a generic extension before sending this set; older peers use native fallback. Explain actual persistence semantics, never invent Session or silently drop Always. |

Advertise only capabilities proven for the installed runtime/plugin. Unsupported is distinct from absent, stale, unreadable or disconnected. Native questions, native approvals and sandbox policy requests keep separate authority and typed results. No automatic retry of ambiguous native decisions or routine mutations. The experimental Plugin SDK requires a tested runtime/plugin compatibility policy and a self-contained package; an incompatible app capability is refused with an actionable reason. ADR 0029's installer-as-served behavior is unchanged; any future runtime-version pin needs an explicit trade-off.

## Implementation order

The [tracking issue](https://github.com/victorbonnet/enclos/issues/218) contains each PR's exact checklist and validation. The stack is:

1. **M5-00:** design and contracts (this document).
2. **M5-01:** protect host OpenClaw state; refresh guidance for immutable snapshots.
3. **M5-02:** disposable macOS prototype using existing `exec`/`connect` sessions, without depending on a future `runtime install openclaw` command.
4. **M5-03–05:** runtime identity/observations, settings/secret consumers, then service/listener contracts, preserving Hermes behavior.
5. **M5-06:** production OpenClaw CLI adapter and Telegram.
6. **M5-07–08:** packaged app channel, richer messages/events, policy context/requests and generic interruption.
7. **M5-09–11:** safe native routines, questions and approvals, with negotiated generic protocol/app changes before native use.
8. **M5-12:** macOS acceptance and operator documentation.
9. **M5-13:** final Linux-specific adjustments and live acceptance on the new host.

Each PR has a reviewable outcome and its own tests/evidence; code cannot rely on an unreviewed later PR. A disproved mandatory outcome needs an explicit scope decision, not a hidden capability removal. No completion claim comes from source reading or an installer exit code alone.

## Acceptance gates

Keep a working Hermes sandbox and create two OpenClaw sandboxes with two agents each. Record installer/runtime/Node/plugin versions, commands, positive controls and results; destructive escape/member experiments remain confined to disposable VMs/CI and signal only test-owned processes.

- Install/setup/create/start without hand-editing managed files; verify native default transitions, separate state/ports and unavailable host state. Failed native operations reconcile correctly.
- Prove protected secrets, missing/rotated-reference behavior, no secret values in argv/startup environments/audit/ordinary settings, two distinct bots and refusal of unlisted people.
- Use the existing paired Android app with Hermes and OpenClaw together: direct/Home/group context, continuation, tools/typing/titles/commands, files/HTML, names/photos/read/archive invariants, policy requests and exact cancellation/fallback.
- Create/edit supported native routines and receive output in the right conversation with the app closed and across bridge/gateway restart. Verify per-operation availability, stale edits, native changes and ambiguous outcomes. Schedules remain with OpenClaw.
- Exercise every advertised question/approval capability, exact receipts/scopes, two-device races, expiry, reconnect/restart and native fallback. Stale controls never resolve newer work.
- Verify service reload/restart, authenticated dashboard, status/doctor/logs, proxy allow/deny controls, unauthorized socket/device refusal, stop/member cleanup within documented lifecycle guarantees and `audit verify`. Hermes's corresponding workflow still works.

Passing these establishes **macOS accepted; Linux pending**. Repeat on the new Linux host with bubblewrap/systemd, shared namespace/relay, actual secret store, dashboard/auth/socket/proxy checks and configured lingering across logout/reboot. Inconclusive probes stay inconclusive. M5 completes only after both gates and all agreed mandatory capabilities have evidence; unsupported or deferred native features stay visible.
