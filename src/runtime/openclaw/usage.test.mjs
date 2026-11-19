import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { agentUsage, day, main, report, write } from './usage.mjs';

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
  // Without `partial`: a cache still refreshing, or a chat not summarized yet
  // (the gateway leaves it out of its sums), is a lower bound too.
  const refreshing = answer({ cacheStatus: { status: 'refreshing', cachedFiles: 2, pendingFiles: 1, staleFiles: 0 } });
  assert.ok(agentUsage(refreshing).models.every(m => m.incomplete?.length === 5));
  const fresh = answer({ cacheStatus: { status: 'fresh', cachedFiles: 2, pendingFiles: 0, staleFiles: 0 } });
  assert.ok(agentUsage(fresh).models.every(m => m.incomplete === undefined));
  fresh.sessions.push({ key: 'agent:main:old', sessionId: 's3', computing: true, usage: null });
  assert.ok(agentUsage(fresh).models.every(m => m.incomplete?.length === 5), 'a listed chat is still computing');
});

test('counts that are not whole numbers of at least 0 are unknown, and past 50 models the rest share a row', () => {
  const a = answer();
  a.aggregates.byModel = Array.from({ length: 60 }, (_, i) =>
    ({ provider: 'p', model: `m${i}`, count: i === 0 ? -1 : 1, totals: totals(100 - i, 0, 0, 0, 0.01) }));
  a.aggregates.byModel[0].totals.output = 1.5;
  const { models } = agentUsage(a);
  assert.equal(models.length, 50);
  assert.equal(models[0].calls, null);
  assert.equal(models[0].tokens.output, null);
  assert.equal(models[49].model, '11 other models');
  assert.equal(models[49].calls, 11);
  assert.equal(models[49].tokens.input, [49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59].reduce((s, i) => s + 100 - i, 0));
  assert.ok(Math.abs(models[49].cost.usd - 0.11) < 1e-9);
  assert.throws(() => agentUsage({ sessions: [] }), /without its aggregates/);
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
  assert.equal(JSON.stringify(read).includes('secret detail'), false);
  assert.equal(JSON.stringify(read).includes('in-memory-fixture-token'), false);
});

test('a gateway that cannot be reached or authenticated is said in the report, not thrown', async () => {
  const cases = [
    [s => { s.env = { OPENCLAW_GATEWAY_PORT: '18789' }; }, /no enclos proxy port/],
    [s => { s.readConfig = async () => ({ snapshot: { valid: false } }); }, /not valid/],
    [s => { s.readConfig = async () => ({ snapshot: { valid: true, sourceConfig: { gateway: {} } } }); }, /token or password authentication/],
    [s => { s.resolveSecret = async () => ({}); }, /gateway secret/],
    [s => { s.callGateway = async () => { throw new Error('ECONNREFUSED'); }; }, /did not answer: start the sandbox/],
  ];
  for (const [change, why] of cases) {
    const s = { ...sdk(), env: { OPENCLAW_GATEWAY_PORT: '43002' } };
    change(s);
    const read = await report({ since: 0, agents: ['main'], ...s });
    assert.deepEqual(read.agents, []);
    assert.match(read.error, why);
  }
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
  assert.equal(read.error, 'OpenClaw is not installed beside the Node that runs it');
});
