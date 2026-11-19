// What the agent's model calls consumed, from OpenClaw's hooks (issue #348,
// docs/protocol.md, Usage). No OpenClaw imports.
//
// As read in 2026.11.5's source (`hook-types.ts`, `attempt-result.ts`,
// `hooks/fire-and-forget.ts`): with OpenClaw's own agent loop, `llm_output`
// fires once per attempt of a run, with the tokens of every call the attempt
// made (its tool loop) summed and no count of them, and runs at once.
// `model_call_started` and `model_call_ended` fire once per call, with its
// run and call ids but no tokens, through a bounded background queue (16 at
// a time, 256 waiting, then dropped), so they can come after the attempt's
// `llm_output`, or never. The plugin keeps a run's calls since its last
// report: those seen to complete, and those seen to start but not yet to
// end. At `llm_output` it reports both as that many calls, and ignores a
// call's end that comes after a report counted it. A call whose end is
// dropped is still counted; a call whose start and end both come only after
// the report counts with the run's next report, if any; a call still running
// at the report that then fails counts too. A run through a CLI backend or
// another harness (`cli-runner.ts`, `harness/lifecycle-hook-helpers.ts`)
// fires `llm_output` without either, so its report counts as one call; a
// `settled-tool-finalization` attempt fires them without `llm_output`, so no
// report counts its calls.
import { message } from './protocol.js';

const line = (text, maximum) => [...String(text).replace(/[\x00-\x1f\x7f-\x9f]/gu, ' ').replace(/\s+/gu, ' ').trim()].slice(0, maximum).join('');
// Runs whose calls are counted at once: a run that never reports its usage
// (an incognito native chat, an attempt skipped) is forgotten past these.
export const MAX_RUNS = 1024;
// The bridge bounds `calls` to this.
const MAX_CALLS = 1000;
// A run's calls kept by id at once, started or reported but not seen to end:
// past these, a start is not kept (its end then counts as a call seen only
// ending) and the oldest reported call is forgotten.
export const MAX_OPEN_CALLS = 64;

/** The record's tokens from OpenClaw's normalized usage, whose `input` is
 * uncached, as enclos counts it; `reasoning`, which it keeps no count of
 * apart from `output`, is left out. */
export function usageTokens(usage) {
  const tokens = {};
  for (const [name, field] of [['input', 'input'], ['output', 'output'], ['cache_read', 'cacheRead'], ['cache_write', 'cacheWrite']]) {
    const value = usage?.[field];
    if (Number.isSafeInteger(value) && value >= 0) tokens[name] = value;
  }
  return tokens;
}

/**
 * Registers the hooks. `appTurn(ctx)` finds the app conversation of a
 * call's native chat, `appSession(ctx)` says the call is in an app
 * conversation's native chat at all, and `running` holds each connected
 * agent's account. Returns whether usage is reported, for the `hello`.
 */
export function registerUsage(api, { appTurn, appSession, assertTurn, running }) {
  if (typeof api.on !== 'function') return false;
  const warned = new Set();
  // Said once per reason, by kind, never with an error's message.
  const warn = (reason, text) => {
    if (warned.has(reason)) return;
    warned.add(reason);
    try { api.logger?.warn?.(`[enclos] ${text}`); } catch { /* A log is never worth a turn. */ }
  };
  // OpenClaw drops `llm_output` for a plugin outside its bundle without this
  // setting, with only a warning of its own: the app would then wait for
  // usage that never comes, so none is announced.
  const config = api.config;
  if (config && typeof config === 'object' && config.plugins?.entries?.enclos?.hooks?.allowConversationAccess !== true) {
    warn('access', 'plugins.entries.enclos.hooks.allowConversationAccess is not true: the app gets no usage from OpenClaw');
    return false;
  }
  // Each run's calls since its last report: `completed`, those seen to
  // complete; `pending`, those seen to start and not to end; `reported`,
  // those a report counted before their end came. The run that saw a call
  // last is the last forgotten.
  const runs = new Map();
  const run = runId => {
    const state = runs.get(runId) ?? { completed: 0, pending: new Set(), reported: new Set() };
    runs.delete(runId);
    runs.set(runId, state);
    if (runs.size > MAX_RUNS) runs.delete(runs.keys().next().value);
    return state;
  };
  // The calls of a run's attempt, at its `llm_output`: those that completed
  // and those yet to end, whose end is then not counted again.
  const report = runId => {
    const state = runs.get(runId);
    if (!state) return undefined;
    const counted = state.completed + state.pending.size;
    for (const callId of state.pending) {
      state.reported.add(callId);
      if (state.reported.size > MAX_OPEN_CALLS) state.reported.delete(state.reported.values().next().value);
    }
    state.completed = 0;
    state.pending.clear();
    if (!state.reported.size) runs.delete(runId);
    return counted;
  };
  api.on('model_call_started', event => {
    try {
      if (typeof event?.runId !== 'string' || typeof event.callId !== 'string') return;
      const { pending } = run(event.runId);
      if (pending.size < MAX_OPEN_CALLS) pending.add(event.callId);
    } catch (error) { warn('count', `counting a model call failed (${error?.name ?? 'Error'})`); }
  });
  api.on('model_call_ended', event => {
    try {
      if (typeof event?.runId !== 'string') return;
      const state = run(event.runId);
      if (typeof event.callId === 'string') {
        // Its attempt's report counted it already.
        if (state.reported.delete(event.callId)) return;
        state.pending.delete(event.callId);
      }
      if (event.outcome === 'completed') state.completed += 1;
    } catch (error) { warn('count', `counting a model call failed (${error?.name ?? 'Error'})`); }
  });
  api.on('llm_output', (event, ctx) => {
    try {
      const counted = typeof event?.runId === 'string' ? report(event.runId) : undefined;
      const tokens = usageTokens(event?.usage);
      if (!Object.keys(tokens).length) return;
      const fields = { tokens };
      const model = event.model ?? ctx?.modelId, provider = event.provider ?? ctx?.modelProviderId;
      if (typeof model === 'string' && line(model, 120)) fields.model = line(model, 120);
      if (typeof provider === 'string' && line(provider, 64)) fields.model_provider = line(provider, 64);
      if (counted > 1) fields.calls = Math.min(counted, MAX_CALLS);
      const turn = appTurn(ctx);
      if (turn) {
        assertTurn(turn);
        if (turn.active.transport.bridgeCapabilities.has('usage')) {
          turn.active.transport.write(message('usage', { conversation: turn.conversation, ...fields }));
        }
        return;
      }
      // An app call whose conversation cannot be told is not sent.
      if (appSession(ctx)) {
        warn('unmatched', 'a model call in an app conversation could not be matched to it: its usage is not passed on');
        return;
      }
      if (typeof ctx?.agentId !== 'string') return;
      const source = ctx.trigger === 'cron' || ctx.trigger === 'heartbeat' ? ctx.trigger : ctx.messageProvider ?? ctx.channel;
      if (typeof source === 'string' && line(source, 32)) fields.source = line(source, 32);
      // Only on the connection of the agent the call is for, once. An agent
      // with no app channel running has none, and the bridge counts nothing.
      for (const active of running.values()) {
        if (active.account.agentId !== ctx.agentId || active.transport.closed) continue;
        if (active.transport.bridgeCapabilities.has('agent_usage')) {
          active.transport.write(message('usage.agent', fields));
        }
        return;
      }
    } catch (error) {
      // Reporting never fails the agent's turn.
      warn('report', `a model call's usage was not passed on (${error?.name ?? 'Error'})`);
    }
  });
  return true;
}
