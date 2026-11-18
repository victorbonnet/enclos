import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelSettings, MAX_MODELS, visible } from '../model.js';
import { message, ProtocolError } from '../protocol.js';

const account = { agentId: 'scout', accountId: 'enclos-scout' };

// OpenClaw's catalogue and config writer, over one config in memory.
function harness({ models = ['model-1', 'model-2'], config } = {}) {
  let cfg = config ?? { agents: { defaults: { model: { primary: 'provider-a/model-1' } }, entries: { scout: {} } } };
  const writes = [], replies = [];
  let current = true;
  const views = view => {
    const all = new Map([['provider-a', new Set(models)], ['provider-b', new Set(['b-1'])], ['bad\u202eid', new Set(['x'])]]);
    const byProvider = view === 'all' ? all : new Map([['provider-a', all.get('provider-a')], ['provider-b', new Set()]]);
    return { providers: [...byProvider.keys()], byProvider, resolvedDefault: { provider: 'provider-a', model: 'model-1' },
      modelNames: new Map([['provider-a/model-2', 'Model Two']]),
      modelMenu: { byProvider: new Map([['provider-b', { available: 0, notice: 'provider-b: missing auth.' }]]) } };
  };
  const runtime = { config: {
    current: () => structuredClone(cfg),
    async mutateConfigFile({ mutate, afterWrite, writeOptions }) {
      assert.deepEqual(afterWrite, { mode: 'auto' }, 'the Gateway decides how to apply it');
      writeOptions.assertCurrent();
      const draft = structuredClone(cfg);
      await mutate(draft, { snapshot: {}, previousHash: null });
      cfg = draft;
      writes.push(draft);
      return { nextConfig: structuredClone(draft), followUp: { mode: 'auto', requiresRestart: false } };
    },
  } };
  const settings = new ModelSettings({ catalogue: async (_cfg, agentId, { view }) => { assert.equal(agentId, 'scout'); return views(view); },
    runtime: () => runtime });
  return { settings, writes, replies, config: () => cfg, change(next) { cfg = next; }, revoke() { current = false; },
    async request(fields) {
      await settings.handle(message('model.request', { person: 'p@example.com', device: 'd', ...fields }),
        { account, assertCurrent() { if (!current) throw new Error('account changed'); }, write(reply) { replies.push(reply); } });
      return replies.at(-1);
    } };
}

test('options list every provider, those the agent cannot use yet disabled with how to set them up', async () => {
  const h = harness();
  const options = await h.request({ action: 'options' });
  assert.equal(options.type, 'model.response');
  assert.equal(options.result, 'options');
  assert.deepEqual(options.current, { provider: 'provider-a', model: 'model-1' });
  assert.equal(options.applies, 'live');
  assert.equal(options.custom_models, false);
  assert.deepEqual(options.providers.map(p => [p.id, p.usable]), [['provider-a', true], ['provider-b', false]], 'a hidden id is left out');
  assert.match(options.providers[1].setup, /missing auth/);
  assert.match(options.providers[1].setup, /openclaw models auth login --provider provider-b --agent scout/);
});

test('models list one provider with its names, cut to the bound', async () => {
  const listed = await harness().request({ action: 'models', provider: 'provider-a' });
  assert.deepEqual(listed.models, [{ id: 'model-1', label: 'model-1' }, { id: 'model-2', label: 'Model Two' }]);
  assert.equal(listed.limited, false);
  const many = Array.from({ length: MAX_MODELS + 10 }, (_, i) => `m-${String(i).padStart(4, '0')}`);
  const long = await harness({ models: many }).request({ action: 'models', provider: 'provider-a' });
  assert.ok(long.models.length <= MAX_MODELS);
  assert.equal(long.limited, true);
  await assert.rejects(harness().request({ action: 'models', provider: 'provider-z' }), e => e instanceof ProtocolError && e.code === 'not_found');
});

test('set writes the agent\'s own primary model and keeps its other model settings', async () => {
  const h = harness({ config: { agents: { defaults: { model: 'provider-a/model-1' }, entries: { scout: { model: { primary: 'provider-a/model-1', fallbacks: ['provider-b/b-1'] } } } } } });
  const { revision } = await h.request({ action: 'options' });
  const set = await h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision });
  assert.equal(set.result, 'set');
  assert.deepEqual(set.previous, { provider: 'provider-a', model: 'model-1' });
  assert.deepEqual(set.current, { provider: 'provider-a', model: 'model-2' });
  assert.notEqual(set.revision, revision);
  assert.equal(set.applies, 'live');
  assert.deepEqual(h.config().agents.entries.scout.model, { primary: 'provider-a/model-2', fallbacks: ['provider-b/b-1'] });
  assert.equal(h.config().agents.defaults.model, 'provider-a/model-1', 'other agents keep the shared default');
});

test('set is refused for a stale revision, a provider not set up, or a model OpenClaw does not list', async () => {
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  await assert.rejects(h.request({ action: 'set', provider: 'provider-b', model: 'b-1', revision }), e => e.code === 'not_allowed');
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'nope', revision }), e => e.code === 'not_found');
  h.change({ agents: { defaults: { model: { primary: 'provider-a/model-2' } }, entries: { scout: {} } } });
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), e => e.code === 'conflict');
  assert.equal(h.writes.length, 0);
});

test('a reconfigured account gets no answer', async () => {
  const h = harness();
  h.revoke();
  await assert.rejects(h.request({ action: 'options' }));
  assert.equal(h.replies.length, 0);
});

test('requests are checked before OpenClaw is asked', async () => {
  const h = harness();
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: '', revision: 'r' }), e => e.code === 'bad_message');
  await assert.rejects(h.request({ action: 'rename' }), e => e.code === 'bad_message');
  assert.equal(h.writes.length, 0);
});

test('without the catalogue or the config writer the capability is off', () => {
  assert.equal(new ModelSettings({ catalogue: undefined, runtime: () => ({ config: { current() {}, mutateConfigFile() {} } }) }).available(), false);
  assert.equal(new ModelSettings({ catalogue: async () => ({}), runtime: () => undefined }).available(), false);
});

test('hidden characters match the bridge\'s rule', () => {
  for (const hidden of ['a\u200bb', 'a\u202eb', 'a\u0007', 'a\ufeff', 'a\u{e0041}']) assert.equal(visible(hidden), false, JSON.stringify(hidden));
  for (const shown of ['provider-a', 'gpt-5.1', 'Mod\u00e8le', '\u30e2\u30c7\u30eb']) assert.equal(visible(shown), true, shown);
});
