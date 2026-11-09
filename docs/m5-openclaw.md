# M5: OpenClaw alongside Hermes

M5 adds OpenClaw through the existing runtime adapter, channel plugin and mobile bridge. The implementation is in the published stack below; this is not a released-build or completed-acceptance claim. [Issue #218](https://github.com/victorbonnet/enclos/issues/218) tracks the milestone. [The acceptance record](m5-openclaw-acceptance.md) separates actual macOS results, repeatable checks and remaining live gates. [The operator guide](openclaw.md) describes the production CLI workflow; [the initial research](research/m5-openclaw-runtime.md) remains source evidence, not live proof.

The stack is rebased onto the requested mobile heads: [enclos #227](https://github.com/victorbonnet/enclos/pull/227), `753fc70084b1233c44632979d616148f1b8eda68`, and [enclos-app #44](https://github.com/victorbonnet/enclos-app/pull/44), `4e53b966253e5e3e0348ceed28cb0858c28b0659`. Each M5 PR builds on its predecessor. Proposed ADRs retain their status; implemented code and passing checks do not blanket-accept a proposal or establish every live behavior.

macOS source implementation is present through M5-11b. Manual macOS acceptance remains incomplete. M5-13, including Linux-specific adjustments and live acceptance, waits for the new Linux host as the final step; no Pi run is required. Cross-platform CI is regression evidence, not live Linux acceptance. Host-service forwards, other runtimes/backends, a general web UI, sharing, iOS and general mobile administration ([#166](https://github.com/victorbonnet/enclos/issues/166)) remain separate work.

## Runtime contracts

The implemented trait is [`src/runtime/mod.rs`](../src/runtime/mod.rs). The changes deepen existing seams using demonstrated Hermes/OpenClaw differences; shared callers retain normalized results instead of native configuration schemas.

| Seam | Implemented ownership | Invariants retained |
| --- | --- | --- |
| Runtime adapter | Native install/mutation commands, agent/default identities, observation decoding, settings, secret consumers, services/listeners and app-channel configuration. | Every command enclos runs is a `SandboxCommand` executed by the engine in a recorded sandbox session. Native paths, parsing and routing remain inside the adapter. Login/talk instructions use native commands. |
| Engine | State, lock, audit, policy, secret-store access, protected I/O and process identity. | Bounded, link-safe observations and printable output. Unknown, missing, unreadable and unsupported remain distinct. Secret values stay out of command arguments, audit, ordinary settings and background service startup environments. |
| Channel plugin | Native account/session mapping, content/events, delivery and native request/control bindings. | Runs inside the sandbox. The bridge dials one authenticated Unix socket per agent. Persist outgoing ids until acknowledgement; do not automatically repeat uncertain native effects. |
| Bridge and app | People/devices, authority, history, Home, names/photos, read state, archives, groups and push. | No native database parsing, second scheduler or general Gateway administration exposed to the phone. Supported controls follow negotiated capabilities. |

### Identity and observations

M5-03 implements `default_agent(home)` independently of an immutable built-in agent, and adapter-owned `fact_value(at, text)` interpretation. Hermes retains its permanent `default`; OpenClaw has no permanent built-in agent. Its implicit `main` can be adopted, and omitted targets resolve the installed native selection instead of a shared literal name. An absent or ambiguous selection is not silently replaced.

The engine retains bounded, link-safe reads and terminal escaping. Dynamic `ValueAt.keys` are opaque selectors interpreted by the adapter. Hermes owns its YAML decoder; the OpenClaw adapter owns bounded JSON5 parsing and its shared native roster/settings. Links, unsupported includes, malformed data and out-of-bound paths remain findings. Native authentication is not inferred from a directory or database merely existing. Partial native creation/removal requires discovery/reconciliation before retrying or recording success.

The newer base's provider-selection observations remain normalized through the same
adapter decoder; the engine does not regain a YAML parser. Agent removal also
declares its lifecycle through `AgentDeleteMode`: Hermes pauses the runtime while
preserving partial-delete recovery, and OpenClaw uses its running authenticated
Gateway without an offline fallback or automatic decision retry.

### Configuration and secrets

M5-04 implements `SecretFiles`/`SecretFileFormat`, protected JSON serialization and runtime-owned `inspect_settings`/`channel_token_is_plain` decoding. Plain settings work without an agent-secret source when the agent has no grants. Hermes retains its existing reader formats and diagnostics. The engine still owns atomic writes, permissions, redaction and cleanup; legacy filenames do not determine their content format.

M5-06 uses native file SecretRefs for the Gateway and per-agent channel consumers. The service reads protected JSON without retaining secret values in its startup environment. Native OAuth remains runtime-owned state inside the sandbox. Native CLI authentication uses the usual `OPENCLAW_GATEWAY_TOKEN` grant; `runtime configure` translates the granted reference rather than writing a literal token. The operator guide keeps credential-only ChatGPT device login separate from model selection and omits the online-incompatible `--set-default` flag.

M5-07 extends `app_channel(agent, socket, token_file, home)` with the explicit core-owned protected credential-file path. OpenClaw receives that path as its per-account `tokenFile`; the adapter does not infer the secret layout from a socket name or reuse Hermes's environment-folder convention.

Per-agent grants provide routing within a sandbox, not isolation between its agents. Telegram configuration sets allowed people, group policy, protected token references and explicit account-to-agent bindings before enabling an account. Unsupported references/values fail before mutation; service setup does not fall back to plaintext or startup-environment credentials. The native owner helper removes agents through the authenticated managed Gateway; uncertain deletion is not automatically replayed. Import through `agent add --from` is explicitly unsupported before staging: Claws and whole-install backups are not a native per-agent/history export under ADR 0026.

### Services, listeners and dashboard

The production adapter runs a foreground Gateway under enclos's service lifecycle, with sandbox-local state/toolchain paths, external-supervisor settings and native hot reload. It does not install an OpenClaw-owned host service or reuse Hermes's USR1 restart signal. The macOS wrapper supplies a readable public CA bundle through native Codex's supported setting when no explicit CA override exists, retaining TLS verification.

`RuntimeListener` now declares `ListenerPorts::Ephemeral` or `SingleLoopback`. Hermes keeps ephemeral selection; OpenClaw uses a positive sandbox-specific port. Candidate selection still requires recorded root-process identity, exclusive ownership, loopback constraints and exclusion of proxy ports. A configured port or TCP accept alone does not establish native authenticated readiness. No broad loopback grant or sandbox-written port file substitutes for ownership.

[Proposed ADR 0055](adr/0055-a-runtime-declares-its-service-listener-selection.md) records the listener-selection amendment. Existing lifetime/reused-port limits and ADR statuses remain explicit. Native dashboard handoff preserves its authentication and one-use privileged browser URL; enclos does not invent an unauthenticated page. The acceptance record retains the unrun dashboard, restart/reload and lifecycle combinations alongside the observed clean stop/restart and authenticated model result.

## Implemented parity and accepted native gaps

This matrix describes source behavior in the stack. Its right column is the remaining live verification, or an explicitly accepted follow-up; it is not a claim that every row has passed on a phone or on Linux.

| Area | Implemented contract | Remaining gate or accepted boundary |
| --- | --- | --- |
| Installation/setup | Official as-served local-prefix runtime-only installer in recorded confined sessions; private Node/runtime/state, native login and installer provenance. Host default OpenClaw state roots are protected. | Recorded macOS install/model evidence exists. Verify two independent sandboxes and custom host-state paths; refresh immutable snapshots after upgrades. |
| Agents/observations | Native create/list/adopt/remove, selected-default resolution, bounded native decoding and status/doctor metadata. | Confirm default transitions, partial failures, unavailable auth facts and independent state/ports across the acceptance setup. |
| Import/export | Typed unsupported import before copying/extracting an archive or mutating the runtime. | Native per-agent export/import remains unavailable; no invented enclos archive format. |
| Service/Telegram | Managed foreground service, verified listener selection, protected SecretRefs, distinct accounts and allowed-person-before-enable ordering. | Real two-bot routing, unlisted-person refusal, missing/rotated references and dashboard/restart combinations remain manual gates. |
| App delivery | Packaged public-SDK plugin; per-agent authenticated socket/account; stable person/conversation native sessions, first-use Home, proactive output, durable ids/replay and incoming deduplication. | Real package loading and main/scout native-command round trips are recorded. Paired-phone continuation, disconnect/restart and scheduled-delivery combinations remain to run. |
| Content/events | Markdown, native typing/tool events/commands, bounded files/static HTML, native title observation and guarded display-title rename/clear. | Verify attribution, rendering and lifetime behavior on the real app. Addressable native labels retain their own meaning; no streaming capability is inferred from a reserved enum. |
| Bridge-owned behavior | Existing names/photos, read state, Home, archives and same-sandbox groups use runtime-neutral paths. | Paired-device and cross-runtime acceptance remains; code reuse does not prove every screen/transition. |
| Cancellation | Negotiated `turn.abort` names the exact original ingress. OpenClaw retains that ingress's public run abort signal; Hermes uses its public lifecycle/interruption helper with task/guard identity checks. The bridge no longer sends a universal `/stop`. | Native admission/signal and stale-target tests exist. Acknowledgement accepts the request, not a drain/hard-kill guarantee. Unsupported interruption finishes and drops the late reply; verify phone/restart cases. |
| Sandbox policy | Persisted active context, explicit scope-request tool and concrete native file-permission observations through existing bridge authority. | No shell-string inference. Run actual allowed/denied operations and phone decisions; native runtime consent remains separate. |
| Routines | Native scheduler inventory and supported full definitions are read-only, using the public service-owned cron handle. Per-operation metadata gates model requests and app controls; native fields/destinations are preserved. | Accepted M5 boundary: no app create/update/pause/delete/run. Richer safe operations are [#226](https://github.com/victorbonnet/enclos/issues/226). Verify read-only inventory/details and native scheduled delivery live. |
| Questions | Complete native text fallback, preserving batches/multiple selections and trusted Control UI credential instructions. No structured `questions` capability or second question tool. | Accepted M5 boundary: richer cards are [#225](https://github.com/victorbonnet/enclos/issues/225). Hosted helper ownership is source-backed; canonical read/reconciliation, offered controls and typed terminal semantics still need a faithful card contract. |
| Runtime approvals | Independently negotiated `runtime_approval_scopes`, exact native request/account/conversation/person binding, complete literal command and native persistence explanation, durable receipts and old-peer fallback. OpenClaw's Once/Always/Deny does not invent Session. | Public-SDK lifecycle/authority/race tests exist. Verify actual native decisions, two devices, external settlement, expiry/restart and fallback on the paired app. Consent is not proof that execution succeeded. |

The runtime installer remains official/as served under ADR 0029. Experimental SDK/helper surfaces use an explicitly tested runtime pair (OpenClaw 2026.11.2); incompatible surfaces refuse with actionable guidance. The shipped JavaScript package has its own build/import-closure checks and does not assume upstream development dependencies.

Only supported native request shapes get structured approval controls. The public `approval.native` capability supplies narrow native resolution ownership; no general Gateway RPC authority reaches the phone. Descriptions/actions remain immutable, old peers receive complete native fallback, and ambiguous native decisions are never automatically retried. [Proposed ADR 0056](adr/0056-native-approval-scopes-are-explicitly-negotiated.md) records the negotiated extension. Retained independent-scope history/cache requires compatible readers on rollback.

## Implementation order

The host stack is published in this order; each PR carries its own changes and evidence. The prototype PR remains draft. PR readiness, code implementation, ADR acceptance and full live acceptance are separate states.

| Step | Published PR | Scope |
| --- | --- | --- |
| M5-00 | [#219](https://github.com/victorbonnet/enclos/pull/219) | Design/contracts and acceptance plan. |
| M5-01 | [#220](https://github.com/victorbonnet/enclos/pull/220) | Host OpenClaw state protection and policy refresh. |
| M5-02 | [#221](https://github.com/victorbonnet/enclos/pull/221), draft | Disposable macOS install/Gateway prototype and evidence. |
| M5-03 | [#222](https://github.com/victorbonnet/enclos/pull/222) | Native identities, observation interpretation and defaults. |
| M5-04 | [#223](https://github.com/victorbonnet/enclos/pull/223) | Runtime secret consumers, settings and diagnostics. |
| M5-05 | [#224](https://github.com/victorbonnet/enclos/pull/224) | Runtime listener selection. |
| M5-06 | [#228](https://github.com/victorbonnet/enclos/pull/228) | Isolated CLI adapter, operator guide, native owner deletion and Telegram. |
| M5-07 | [#229](https://github.com/victorbonnet/enclos/pull/229) | Packaged authenticated app channel and explicit credential-file path. |
| M5-08 | [#230](https://github.com/victorbonnet/enclos/pull/230) | Native work/events, files and sandbox policy requests. |
| M5-09 | [#231](https://github.com/victorbonnet/enclos/pull/231) | Read-only native routines and optional operation metadata. |
| M5-10 | [#232](https://github.com/victorbonnet/enclos/pull/232) | Complete native question text and native session display titles. |
| M5-11a | [#233](https://github.com/victorbonnet/enclos/pull/233) | Generic independently negotiated native approval scopes. |
| M5-11b | [#234](https://github.com/victorbonnet/enclos/pull/234) | Native approval lifecycle, exact cancellation and deployment assets. |

The app companion stack is [#42](https://github.com/victorbonnet/enclos-app/pull/42) → [#45](https://github.com/victorbonnet/enclos-app/pull/45) (routine operations) → [#46](https://github.com/victorbonnet/enclos-app/pull/46) (native approval scopes). Android build/unit/lint and remote CI have passed for the companions; physical-device and iOS coverage remain distinct.

**M5-12** maintains [the acceptance record](m5-openclaw-acceptance.md), final regression evidence and outstanding manual macOS checks. **M5-13** is the final Linux-specific implementation/acceptance on the new host. Neither the original planning research nor one successful model call completes those gates.

## Acceptance gates

Keep a working Hermes sandbox and use two independently installed OpenClaw sandboxes with two agents each. Record actual installer/runtime/Node/plugin versions, commands, positive controls and results. Destructive escape/member experiments remain confined to disposable VMs/CI and signal only test-owned processes.

- Install/setup/create/start through production interfaces; verify native defaults, separate state/ports, protected host state and partial-failure reconciliation.
- Prove granted file references, missing/rotated credentials, no values in ordinary settings/argv/audit/service startup environments, distinct Telegram bots and refusal of unlisted people.
- Use the paired Android app with Hermes and OpenClaw: direct/Home/group context, continuation, names/photos/read/archive behavior, commands, tools/typing/titles, files/static HTML, policy requests and exact cancellation/fallback.
- Inspect read-only native routine inventory/details and unsupported schedules. Create schedules through authorized native tools where needed, then verify native delivery with the phone/bridge away and across restart. App mutations are the separate #226 follow-up.
- Exercise native approval scopes/receipts, two-device races, external settlement, expiry/restart and older-peer fallback. Verify complete native question text and trusted credential-request instructions; structured cards are the separate #225 follow-up. Stale controls must not resolve newer work.
- Verify authenticated dashboard handoff, status/doctor/logs, proxy allow/deny, unauthorized socket/device refusal, audit verification and reload/restart/member cleanup within documented lifecycle guarantees. Preserve the corresponding Hermes workflow.

Until those manual gates pass, report **macOS acceptance incomplete; Linux pending**. Only then can macOS be accepted independently. Repeat on the new Linux host with real bubblewrap/systemd, shared namespace/relay, secret store, dashboard/auth/socket/proxy and configured lingering across logout/reboot. Inconclusive probes stay inconclusive. M5 remains open until both gates and the agreed scope have evidence; #225/#226 stay explicit follow-ups rather than hidden or fabricated capabilities.
