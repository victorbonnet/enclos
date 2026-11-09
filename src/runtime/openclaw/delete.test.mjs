import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deleteAgent } from './delete.mjs';

function fixture() {
  const ref = { source: 'file', provider: 'enclos-sandbox', id: '/OPENCLAW_GATEWAY_TOKEN' };
  const sourceConfig = { gateway: { mode: 'local', auth: { mode: 'token', token: ref } } };
  const calls = [], resolutions = [];
  return { sourceConfig, calls, resolutions,
    params: { agentId: 'checker', env: { OPENCLAW_GATEWAY_PORT: '43002' },
      readConfig: async () => ({ snapshot: { valid: true, sourceConfig } }),
      resolveSecret: async input => { resolutions.push(input); return { value: 'in-memory-fixture-token' }; },
      callGateway: async (method, opts, params) => { calls.push({ method, opts, params }); return { removed: [], failed: [] }; } } };
}

test('owner deletion resolves the configured native ref and authenticates only the exact local Gateway', async () => {
  const f = fixture(), before = structuredClone(f.sourceConfig), envBefore = structuredClone(f.params.env);
  assert.deepEqual(await deleteAgent(f.params), { agentId: 'checker', transport: 'gateway', removed: [], failed: [] });
  assert.deepEqual(f.calls.map(c => c.method), ['health', 'agents.delete']);
  assert.equal(f.resolutions[0].value, f.sourceConfig.gateway.auth.token);
  assert.equal(f.calls[0].opts.token, 'in-memory-fixture-token');
  assert.equal(f.calls[1].opts.expectUrl, 'ws://127.0.0.1:43002');
  assert.equal(f.calls[1].opts.port, '43002');
  assert.deepEqual(f.calls[1].params, { agentId: 'checker', deleteFiles: true });
  assert.deepEqual(f.sourceConfig, before);
  assert.deepEqual(f.params.env, envBefore);
});

test('missing auth, wrong target and failed readiness refuse before mutation', async () => {
  for (const invalidate of [f => { f.sourceConfig.gateway.mode = 'remote'; }, f => { f.params.env.OPENCLAW_GATEWAY_PORT = '18789'; }, f => { f.params.resolveSecret = async () => ({}); }, f => { f.params.callGateway = async (method) => { f.calls.push({ method }); throw new Error('failure'); }; }]) {
    const f = fixture(); invalidate(f);
    await assert.rejects(deleteAgent(f.params), /Start this sandbox/);
    assert.equal(f.calls.some(c => c.method === 'agents.delete'), false);
  }
});

test('an ambiguous native deletion failure is never retried or sent through another route', async () => {
  const f = fixture();
  f.params.callGateway = async method => { f.calls.push({ method }); if (method === 'agents.delete') throw new Error('connection lost'); return {}; };
  await assert.rejects(deleteAgent(f.params));
  assert.deepEqual(f.calls.map(c => c.method), ['health', 'agents.delete']);
});
