import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { agentUsage, day, main, report, write } from './usage.mjs';

// The report the reader writes for `contract()`'s answers, which the host's
// parser reads in `src/engine/usage.rs` (`the_openclaw_readers_report_is_taken`).
const CONTRACT = new URL('./usage-report.json', import.meta.url);

const totals = (input, output, cacheRead, cacheWrite, totalCost, missingCostEntries = 0) =>
  ({ input, output, cacheRead, cacheWrite, totalTokens: input + output + cacheRead + cacheWrite, totalCost, missingCostEntries });

// The shape of OpenClaw 2026.11.5's `sessions.usage` answer
// (`src/shared/usage-types.ts`), cut to what the reader uses.
function answer(fields = {}) {
  return {
    updatedAt: 0, startDate: '2026-11-12', endDate: '2026-11-19',
    totals: totals(0, 0, 0, 0, 0),
    aggregates: {
      byModel: [
        { provider: 'anthropic', model: 'claude-sonnet-5-5', count: 12, totals: totals(5000, 900, 80000, 3000, 0.42) },
        { provider: 'openai', model: 'gpt-6.1', count: 3, totals: totals(1000, 200, 0, 0, 0, 3) },
      ],
    },
    sessions: [
      { key: 'agent:main:enclos:direct:abc', sessionId: 's1', label: 'Weather\u001b[31m', channel: 'enclos', model: 'claude-sonnet-5-5',
        usage: { ...totals(4000, 800, 70000, 3000, 0.4), firstActivity: 1763164800500, messageCounts: { assistant: 10 },
          modelUsage: [{ provider: 'anthropic', model: 'claude-sonnet-5-5', count: 10, totals: totals(4000, 800, 70000, 3000, 0.4) }] } },
      { key: 'agent:main:cron:daily', sessionId: 's2', channel: 'cron', model: 'gpt-6.1',
        usage: { ...totals(2000, 300, 10000, 0, 0.02), firstActivity: 1763251200000, messageCounts: { assistant: 5 },
          modelUsage: [
            { provider: 'anthropic', model: 'claude-sonnet-5-5', count: 2, totals: totals(1000, 100, 10000, 0, 0.02) },
            { provider: 'openai', model: 'gpt-6.1', count: 3, totals: totals(1000, 200, 0, 0, 0, 3) }] } },
    ],
    ...fields,
  };
}

test('an agent\'s answer becomes its models and top chats, with what OpenClaw does not count left unknown', () => {
  const read = agentUsage(answer());
  assert.equal(read.found, true);
  assert.deepEqual(read.models, [
    { model: 'claude-sonnet-5-5', model_provider: 'anthropic', chats: 2, calls: 12,
      tokens: { input: 5000, output: 900, cache_read: 80000, cache_write: 3000, reasoning: null },
      cost: { usd: 0.42, kind: 'estimated' } },
    // Every call unpriced: the cost is unknown, not $0.
    { model: 'gpt-6.1', model_provider: 'openai', chats: 1, calls: 3,
      tokens: { input: 1000, output: 200, cache_read: 0, cache_write: 0, reasoning: null },
      cost: { usd: null, kind: 'unknown' } },
  ]);
  assert.deepEqual(read.top.map(c => [c.chat, c.source, c.calls, c.started_at]),
    [['s1', 'enclos', 10, 1763164800.5], ['s2', 'cron', 5, 1763251200]]);
  // Text is passed on as written; enclos escapes it on the host.
  assert.equal(read.top[0].title, 'Weather\u001b[31m');
  assert.equal(read.top[0].tokens.reasoning, null);
});

test('some calls unpriced make a cost mixed; a partial answer marks every count as a lower bound', () => {
  const a = answer({ partial: { reason: 'time-budget', message: 'more' } });
  a.aggregates.byModel = [{ provider: 'anthropic', model: 'm', count: 4, totals: totals(1, 1, 1, 1, 0.5, 1) }];
  const [model] = agentUsage(a).models;
  assert.deepEqual(model.cost, { usd: 0.5, kind: 'mixed' });
  assert.deepEqual(model.incomplete, ['calls', 'input', 'output', 'cache_read', 'cache_write']);
});

test('each sign of an answer not yet whole marks every count as a lower bound, on its own', () => {
  const fresh = { status: 'fresh', cachedFiles: 2, pendingFiles: 0, staleFiles: 0 };
  assert.ok(agentUsage(answer({ cacheStatus: fresh })).models.every(m => m.incomplete === undefined));
  // Without `partial`: the gateway leaves a chat it has not summarized out
  // of its sums, and says so only in these.
  const signs = {
    'a cache refreshing': a => { a.cacheStatus = { ...fresh, status: 'refreshing' }; },
    'files pending': a => { a.cacheStatus = { ...fresh, pendingFiles: 1 }; },
    'files stale': a => { a.cacheStatus = { ...fresh, staleFiles: 1 }; },
    'a chat computing': a => { a.sessions.push({ key: 'agent:main:old', sessionId: 's3', computing: true, usage: null }); },
    'a chat stale': a => { a.sessions[0].usage.staleSince = 1; },
    'a chat refreshing': a => { a.sessions[0].usage.refreshing = true; },
  };
  for (const [sign, change] of Object.entries(signs)) {
    const a = answer({ cacheStatus: fresh });
    change(a);
    assert.ok(agentUsage(a).models.every(m => m.incomplete?.length === 5), sign);
  }
});

test('a cost OpenClaw does not say how many calls it could not price is mixed, not estimated', () => {
  const a = answer();
  a.aggregates.byModel = [{ provider: 'p', model: 'm', count: null, totals: { ...totals(1, 1, 0, 0, 0.2), missingCostEntries: undefined } }];
  assert.deepEqual(agentUsage(a).models[0].cost, { usd: 0.2, kind: 'mixed' });
});

test('the top chats are the 5 that used the most, and a start time the host cannot take is unknown', () => {
  const a = answer();
  const order = [3, 6, 0, 5, 1, 4, 2];
  a.sessions = order.map(i => ({ key: `k${i}`, sessionId: `s${i}`, channel: 'cron',
    usage: { ...totals(1000 * (i + 1), 0, 0, 0, 0), firstActivity: i === 6 ? 1e20 : 1763164800000, messageCounts: { assistant: 1 }, modelUsage: [] } }));
  const { top } = agentUsage(a);
  assert.deepEqual(top.map(c => c.chat), ['s6', 's5', 's4', 's3', 's2']);
  assert.equal(top[0].started_at, null);
  assert.equal(top[1].started_at, 1763164800);
});

/** `n` models, the i-th of `1000 - i` input tokens, in a shuffled order. */
function models(n) {
  const rows = Array.from({ length: n }, (_, i) =>
    ({ provider: 'p', model: `m${i}`, count: 1, totals: totals(1000 - i, 0, 0, 0, 0.01) }));
  for (let i = rows.length - 1; i > 0; i--) {
    const j = (i * 7919) % (i + 1);
    [rows[i], rows[j]] = [rows[j], rows[i]];
  }
  return rows;
}

test('counts that are not whole numbers of at least 0 are unknown, and past 50 models the rest share a row', () => {
  const a = answer();
  a.aggregates.byModel = models(60);
  const first = a.aggregates.byModel.find(m => m.model === 'm0');
  first.count = -1;
  first.totals.output = 1.5;
  const read = agentUsage(a).models;
  assert.equal(read.length, 50);
  // Heaviest first, whatever order OpenClaw gave.
  assert.deepEqual(read.slice(0, 49).map(m => m.model), Array.from({ length: 49 }, (_, i) => `m${i}`));
  assert.equal(read[0].calls, null);
  assert.equal(read[0].tokens.output, null);
  assert.equal(read[49].model, '11 other models');
  assert.equal(read[49].calls, 11);
  assert.equal(read[49].tokens.input, Array.from({ length: 11 }, (_, i) => 1000 - 49 - i).reduce((s, v) => s + v, 0));
  assert.ok(Math.abs(read[49].cost.usd - 0.11) < 1e-9);
  assert.equal(read[49].cost.kind, 'estimated');
  assert.equal(read[49].incomplete, undefined);
});

test('the folded row keeps what its rows do not know, and folds only past 50', () => {
  for (const [n, folded] of [[50, null], [51, '2 other models']]) {
    const a = answer();
    a.aggregates.byModel = models(n);
    const read = agentUsage(a).models;
    assert.equal(read.length, 50);
    assert.equal(read[49].model, folded ?? 'm49');
  }
  const a = answer({ partial: { reason: 'time-budget', message: 'more' } });
  a.aggregates.byModel = models(55);
  const unpriced = a.aggregates.byModel.find(m => m.model === 'm54');
  unpriced.count = null;
  unpriced.totals = { ...unpriced.totals, totalCost: 0, cacheRead: undefined, missingCostEntries: 1 };
  const row = agentUsage(a).models[49];
  assert.equal(row.calls, null);
  assert.equal(row.tokens.cache_read, null);
  assert.equal(row.tokens.input, Array.from({ length: 6 }, (_, i) => 1000 - 49 - i).reduce((s, v) => s + v, 0));
  assert.equal(row.cost.kind, 'mixed');
  assert.deepEqual(row.incomplete, ['calls', 'input', 'output', 'cache_read', 'cache_write']);
});

test('an answer without per-model sums is an error, never an agent that used nothing', () => {
  for (const bad of [null, {}, { sessions: [] }, { aggregates: {}, sessions: [] }, { aggregates: { byModel: {} }, sessions: [] }]) {
    assert.throws(() => agentUsage(bad), /without its per-model sums/);
  }
});

function sdk(answers = {}) {
  const calls = [];
  return { calls,
    readConfig: async () => ({ snapshot: { valid: true, sourceConfig: { gateway: { mode: 'local', auth: { mode: 'token', token: { source: 'file', provider: 'enclos-sandbox', id: '/OPENCLAW_GATEWAY_TOKEN' } } } } } }),
    resolveSecret: async () => ({ value: 'in-memory-fixture-token' }),
    callGateway: async (method, opts, params) => {
      calls.push({ method, opts, params });
      const value = method === 'health' ? {} : answers[params.agentId];
      if (value instanceof Error) throw value;
      return value;
    } };
}

test('each agent is asked of the exact local gateway, by UTC day, and one that fails is said alone', async () => {
  const failed = Object.assign(new Error('secret detail of the settings'), { gatewayCode: 'INVALID_REQUEST' });
  const s = sdk({ main: answer(), scout: failed });
  const read = await report({ since: 1763164800 + 3600, agents: ['main', 'scout'], ...s,
    env: { OPENCLAW_GATEWAY_PORT: '43002' }, now: Date.UTC(2026, 10, 19, 12) });
  assert.deepEqual(s.calls.map(c => c.method), ['health', 'sessions.usage', 'sessions.usage']);
  assert.equal(s.calls[1].opts.token, 'in-memory-fixture-token');
  assert.equal(s.calls[1].opts.expectUrl, 'ws://127.0.0.1:43002');
  assert.deepEqual(s.calls[1].params, { agentId: 'main', startDate: '2025-11-15', endDate: '2026-11-19', mode: 'utc', limit: 100 });
  assert.equal(read.format, 1);
  assert.equal(read.agents[0].agent, 'main');
  assert.equal(read.agents[0].models.length, 2);
  assert.deepEqual(read.agents[1], { error: 'sessions.usage failed: INVALID_REQUEST', agent: 'scout' });
  // One agent's answer of another shape, or an error without a code, is
  // said for it alone.
  const odd = sdk({ main: null, scout: new TypeError('socket closed: secret detail'), writer: answer() });
  const mixed = await report({ since: 0, agents: ['main', 'scout', 'writer'], ...odd, env: { OPENCLAW_GATEWAY_PORT: '43002' } });
  assert.deepEqual(mixed.agents.map(a => a.error ?? 'read'),
    ['OpenClaw answered sessions.usage without its per-model sums', 'sessions.usage failed (TypeError)', 'read']);
  assert.equal(JSON.stringify(mixed).includes('secret detail'), false);
  assert.equal(JSON.stringify(read).includes('secret detail'), false);
  assert.equal(JSON.stringify(read).includes('in-memory-fixture-token'), false);
});

test('a gateway that cannot be reached or authenticated is said in the report, not thrown', async () => {
  const settings = gateway => async () => ({ snapshot: { valid: true, sourceConfig: { gateway } } });
  const cases = [
    [s => { s.env = { OPENCLAW_GATEWAY_PORT: '18789' }; }, /no enclos proxy port/],
    [s => { s.env = { OPENCLAW_GATEWAY_PORT: '43002x' }; }, /no enclos proxy port/],
    [s => { s.env = { OPENCLAW_GATEWAY_PORT: '44000' }; }, /no enclos proxy port/],
    [s => { s.env = {}; }, /no enclos proxy port/],
    [s => { s.readConfig = async () => { throw new SyntaxError('secret detail'); }; }, /^OpenClaw could not read its settings \(SyntaxError\)$/],
    [s => { s.readConfig = async () => ({ snapshot: { valid: false } }); }, /not valid/],
    [s => { s.readConfig = settings({ mode: 'remote', auth: { mode: 'token', token: 'x' } }); }, /remote/],
    [s => { s.readConfig = settings({}); }, /token or password authentication/],
    [s => { s.resolveSecret = async () => ({}); }, /^OpenClaw could not resolve its gateway token$/],
    [s => { s.resolveSecret = async () => { throw new Error('secret detail'); }; }, /^OpenClaw could not resolve its gateway token \(Error\)$/],
    [s => { s.callGateway = async () => { throw new Error('ECONNREFUSED'); }; }, /did not answer \(Error\): start the sandbox/],
    // A gateway that answers with an error is running: its code is said.
    [s => { s.callGateway = async () => { throw Object.assign(new Error('secret detail'), { gatewayCode: 'UNAUTHORIZED' }); }; },
      /^OpenClaw's gateway refused enclos's request: UNAUTHORIZED$/],
  ];
  for (const [change, why] of cases) {
    const s = { ...sdk(), env: { OPENCLAW_GATEWAY_PORT: '43002' } };
    change(s);
    const read = await report({ since: 0, agents: ['main'], ...s });
    assert.deepEqual(read.agents, []);
    assert.match(read.error, why);
    assert.equal(read.error.includes('secret detail'), false);
  }
});

/** The answers behind `usage-report.json`. */
function contract() {
  const partial = answer({ partial: { reason: 'time-budget', message: 'more' } });
  partial.aggregates.byModel = [{ provider: 'openai', model: 'gpt-6.1', count: 2, totals: totals(10, 2, 0, 0, 0.001, 1) }];
  return sdk({ main: answer(), scout: Object.assign(new Error('x'), { gatewayCode: 'INVALID_REQUEST' }), writer: partial });
}

test('the report is the one the host\'s parser is tested with', async () => {
  const read = await report({ since: 1763164800, agents: ['main', 'scout', 'writer'], ...contract(),
    env: { OPENCLAW_GATEWAY_PORT: '43002' }, now: Date.UTC(2026, 10, 19, 12) });
  if (process.env.ENCLOS_WRITE_CONTRACT === '1') writeFileSync(CONTRACT, JSON.stringify(read, null, 2) + '\n');
  assert.deepEqual(read, JSON.parse(readFileSync(CONTRACT, 'utf8')));
});

test('the window starts at the UTC day that holds it', () => {
  assert.equal(day(1763164800), '2025-11-15');
  assert.equal(day(1763164799), '2025-11-14');
});

test('the report is a new plain file, never one already there or a link', t => {
  const folder = mkdtempSync(path.join(tmpdir(), 'enclos-openclaw-usage-'));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const out = path.join(folder, 'report.json');
  write(out, { format: 1, agents: [] });
  assert.deepEqual(JSON.parse(readFileSync(out, 'utf8')), { format: 1, agents: [] });
  assert.throws(() => write(out, {}), /EEXIST/);
  const target = path.join(folder, 'target');
  writeFileSync(target, 'kept');
  symlinkSync(target, path.join(folder, 'link'));
  assert.throws(() => write(path.join(folder, 'link'), {}));
  assert.equal(readFileSync(target, 'utf8'), 'kept');
});

test('a reader that cannot load OpenClaw still writes why', async t => {
  // This test's Node is no OpenClaw install: its SDK cannot be found.
  const folder = mkdtempSync(path.join(tmpdir(), 'enclos-openclaw-usage-'));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const out = path.join(folder, 'report.json');
  await main([out, '0', 'main']);
  const read = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(read.format, 1);
  assert.deepEqual(read.agents, []);
  assert.equal(read.error, 'OpenClaw is not installed in the Node that runs it');
  // A start that is not a time is said before OpenClaw is looked for.
  const bad = path.join(folder, 'bad.json');
  await main([bad, 'abc', 'main']);
  assert.equal(JSON.parse(readFileSync(bad, 'utf8')).error, 'the window\'s start is not a time');
});
