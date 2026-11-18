import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deleteAgent, ownerSdk } from './delete.mjs';

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

test('unusable settings and a failed readiness check report why mutation was refused', async () => {
  const cases = [
    [f => { f.params.readConfig = async () => ({ snapshot: { valid: false } }); }, /invalid native settings/],
    [f => { f.sourceConfig.gateway.mode = 'remote'; }, /requires a local Gateway/],
    [f => { delete f.sourceConfig.gateway.auth; }, /requires Gateway token or password/],
    [f => { f.params.env.OPENCLAW_GATEWAY_PORT = '18789'; }, /Start this sandbox/],
    [f => { f.params.resolveSecret = async () => ({}); }, /could not resolve its configured Gateway secret/],
    [f => { f.params.callGateway = async method => { f.calls.push({ method }); throw new Error('failure'); }; }, /Start this sandbox/],
  ];
  for (const [invalidate, message] of cases) {
    const f = fixture();
    invalidate(f);
    await assert.rejects(deleteAgent(f.params), message);
    assert.equal(f.calls.some(c => c.method === 'agents.delete'), false);
  }
});

test('an ambiguous native deletion failure is never retried or sent through another route', async () => {
  const f = fixture();
  f.params.callGateway = async method => { f.calls.push({ method }); if (method === 'agents.delete') throw new Error('connection lost'); return {}; };
  await assert.rejects(deleteAgent(f.params));
  assert.deepEqual(f.calls.map(c => c.method), ['health', 'agents.delete']);
});

test('the owner helper checks the minimum and names a missing native capability', async () => {
  const sdk = {
    'config-mutation': { readConfigFileSnapshotForWrite() {} },
    'secret-input-runtime': { resolveConfiguredSecretInputString() {} },
    'gateway-runtime': { callGatewayFromCli() {} },
  };
  const load = async name => sdk[name];
  await assert.rejects(ownerSdk('2026.11.3', load), /Update OpenClaw to 2026.11.5 or newer/);
  assert.equal((await ownerSdk('2026.11.10', load)).callGateway, sdk['gateway-runtime'].callGatewayFromCli);
  sdk['gateway-runtime'] = {};
  await assert.rejects(ownerSdk('2026.11.10', load), /missing callGatewayFromCli/);
});
