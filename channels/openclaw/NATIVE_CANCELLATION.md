# Exact native cancellation

The plugin leg accepts `turn.abort` with `conversation` and `of`, where `of` is
the exact original `message.in` id. The bridge sends it for the running member of
a stopped group only when the plugin advertises `abort`. It cancels the bridge's
queued discussion work and drops late replies independently of native support.
An older plugin receives no invented text command. Its already-running native
work may finish; updating its plugin/native compatibility pair enables targeted
interruption.

Missing, completed, repeated and mismatched targets never select a current run
by conversation alone. An `ack` accepts the cancellation request; it is not a
receipt that native cleanup has drained, tools have exited or a thread was killed.
No runtime command spelling lives in the bridge.

## OpenClaw 2026.11.2

The public `GetReplyOptions.abortSignal` is documented as the signal for the
underlying agent run. `channel.inbound.dispatch` accepts it in `replyOptions`.
The channel retains an `AbortController` for each exact incoming id throughout
asynchronous ingress preparation and native dispatch. Cancellation looks up only
that controller and signals it synchronously after checking current account
authority and conversation. Preparation and delivery check the same signal.
Settlement retires that id; account shutdown signals all of its remaining owned
controllers. No active-session lookup, private native run registry or Gateway
method is used.

The installed public SDK test executes the actual `dispatchChannelInboundTurn`
with an isolated native store and a public injected `replyResolver`. Three
ingresses share one native session: the second is cancelled while queued and
never reaches its resolver; the first's signal remains live until its own
cancellation; a third subsequently starts with an unaffected signal. These are
real native admission/reply-operation boundaries without a model or credential
call. Channel socket tests separately prove wire-to-signal correlation, a wrong
conversation, stale/repeated ids and cancellation during ingress preparation.

Source-labelled native sections inspected: `src/auto-reply/types.ts`
(`GetReplyOptions`), `src/plugin-sdk/reply-options.ts`,
`src/channels/turn/lifecycle.ts`, and `src/auto-reply/reply/dispatch-from-config.ts`.
Native dispatch propagates the exact upstream signal through pre-dispatch
admission, its owned reply operation, queued follow-ups and underlying execution.

## Hermes compatibility

Pinned source: `9dcf7714df7a0d49c335925d12d4b017274ee355`.
`BasePlatformAdapter` exposes `on_processing_start`, `on_processing_complete`
and `interrupt_session_activity`. The start hook precedes its native message
handler. The interruption helper sets the active native `asyncio.Event`
synchronously before its first await, then stops typing. The native turn monitor
observes this event and calls `interrupt` on its captured agent.

The adapter tracks only its original `MessageEvent` objects. An exact request
cancelled before native processing starts exits at the start hook. A native text
batch whose text no longer equals that original ingress is never cancelled on
the strength of one constituent id. For an already-started ingress, read-only
identity checks of native `_session_tasks` and `_active_sessions` retain its
original task and guard. Those checks and the public helper's synchronous signal
run on one event loop without an intervening await. A replaced guard/task cannot
receive an old stop. Completion retires only the matching original event.

Those two read-only native maps are an experimental Hermes compatibility seam,
not a replacement session store. Feature detection requires both public lifecycle
hooks, the public interruption helper and those maps before advertising `abort`.
Older native versions keep their ordinary channel behavior and advertise no
targeted interruption. No `/stop` parser, private worker mutation or broad
session command is introduced.

Python tests execute the exact pinned public helper extracted from
`gateway/platforms/base.py`, alongside focused real-event-loop identity tests.
The native monitor behavior is source-backed by
`gateway/run_turn.py:_run_agent_monitor_for_interrupt` and
`_run_agent_fire_pending_interrupt`; this does not claim a live model interruption
or hard-kill guarantee. Set `ENCLOS_HERMES_APPROVAL_SOURCE` to that pinned source
when running the optional helper tests.
