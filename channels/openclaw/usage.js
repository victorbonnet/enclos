// What the agent's model calls consumed, from OpenClaw's hooks (issue #348,
// docs/protocol.md, Usage). No OpenClaw imports.
//
// OpenClaw's `llm_output` fires once per attempt of a run, with the tokens
// of every call the attempt made (its tool loop) summed, and no count of
// them; `model_call_ended` fires once per call, with its run but no tokens
// (both read in 2026.11.5's `hook-types.ts` and `attempt-result.ts`). The
// plugin counts a run's completed calls until its `llm_output`, which then
// goes as one report of that many calls.
import { message } from './protocol.js';

const line = (text, maximum) => [...String(text).replace(/[\x00-\x1f\x7f-\x9f]/gu, ' ').replace(/\s+/gu, ' ').trim()].slice(0, maximum).join('');
// Runs whose calls are counted at once: a run that never reports its usage
// (an incognito session, an attempt skipped) is forgotten past these.
const MAX_RUNS = 1024;
// The bridge bounds `calls` to this.
const MAX_CALLS = 1000;

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
 * call's session, `appSession(ctx)` says the call is in one at all, and
 * `running` holds each connected agent's account. Returns whether usage is
 * reported, for the `hello`.
 */
export function registerUsage(api, { appTurn, appSession, assertTurn, running }) {
  if (typeof api.on !== 'function') return false;
  const calls = new Map();
  api.on('model_call_ended', event => {
    try {
      if (event?.outcome !== 'completed' || typeof event.runId !== 'string') return;
      const counted = (calls.get(event.runId) ?? 0) + 1;
      calls.delete(event.runId);
      calls.set(event.runId, counted);
      if (calls.size > MAX_RUNS) calls.delete(calls.keys().next().value);
    } catch { /* Counting never changes the native call. */ }
  });
  api.on('llm_output', (event, ctx) => {
    try {
      const counted = typeof event?.runId === 'string' ? calls.get(event.runId) : undefined;
      if (counted != null) calls.delete(event.runId);
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
      if (appSession(ctx) || typeof ctx?.agentId !== 'string') return;
      const source = ctx.trigger === 'cron' || ctx.trigger === 'heartbeat' ? ctx.trigger : ctx.messageProvider ?? ctx.channel;
      if (typeof source === 'string' && line(source, 32)) fields.source = line(source, 32);
      // Only on the connection of the agent the call is for, once.
      for (const active of running.values()) {
        if (active.account.agentId !== ctx.agentId || active.transport.closed) continue;
        if (active.transport.bridgeCapabilities.has('agent_usage')) {
          active.transport.write(message('usage.agent', fields));
        }
        return;
      }
    } catch { /* Reporting never fails the agent's turn. */ }
  });
  return true;
}
