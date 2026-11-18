import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelSettings, MAX_MODELS, visible, agentEntry } from '../model.js';
import { message, ProtocolError } from '../protocol.js';

const account = { agentId: 'scout', accountId: 'enclos-scout' };

// OpenClaw's catalogue and config writer, over one config in memory.
function harness({ models = ['model-1', 'model-2'], config, requiresRestart = false, catalogue } = {}) {
  let cfg = config ?? { agents: { defaults: { model: { primary: 'provider-a/model-1' } }, entries: { scout: {} } } };
  const writes = [], replies = [];
  let current = true, beforeMutate, mutateError, afterWrite;
  const views = view => {
    const all = new Map([['provider-a', new Set(models)], ['provider-b', new Set(['b-1'])], ['bad\u202eid', new Set(['x'])]]);
    const byProvider = view === 'all' ? all : new Map([['provider-a', all.get('provider-a')], ['provider-b', new Set()]]);
    return { providers: [...byProvider.keys()], byProvider, resolvedDefault: { provider: 'provider-a', model: 'model-1' },
      modelNames: new Map([['provider-a/model-2', 'Model Two']]),
      modelMenu: { byProvider: new Map([['provider-b', { available: 0, notice: 'provider-b: missing auth.' }]]) } };
  };
  const runtime = { config: {
    current: () => structuredClone(cfg),
    async mutateConfigFile({ mutate, afterWrite: policy, writeOptions }) {
      assert.deepEqual(policy, { mode: 'auto' }, 'the Gateway decides how to apply it');
      writeOptions.assertCurrent();
      beforeMutate?.();
      const draft = structuredClone(cfg);
      await mutate(draft, { snapshot: {}, previousHash: null });
      if (mutateError) throw mutateError;
      cfg = draft;
      writes.push(draft);
      afterWrite?.();
      return { nextConfig: structuredClone(draft), followUp: { mode: 'auto', requiresRestart } };
    },
  } };
  const settings = new ModelSettings({
    catalogue: catalogue ?? (async (_cfg, agentId, { view }) => { assert.equal(agentId, 'scout'); return views(view); }),
    runtime: () => runtime });
  return { settings, writes, replies, config: () => cfg, change(next) { cfg = next; }, revoke() { current = false; },
    beforeMutate(f) { beforeMutate = f; }, failWrite(error) { mutateError = error; }, afterWrite(f) { afterWrite = f; },
    async request(fields) {
      await settings.handle(message('model.request', { person: 'p@example.com', device: 'd', ...fields }),
        { account, assertCurrent() { if (!current) throw new Error('enclos channel account was stopped or reconfigured'); },
          write(reply) { replies.push(reply); } });
      return replies.at(-1);
    } };
}

const code = expected => error => error instanceof ProtocolError && error.code === expected;

test('options list every model provider, those the agent cannot use yet disabled with how to set them up', async () => {
  const h = harness();
  assert.equal(h.settings.available(), true);
  const options = await h.request({ action: 'options' });
  assert.equal(options.type, 'model.response');
  assert.equal(options.result, 'options');
  assert.deepEqual(options.current, { provider: 'provider-a', model: 'model-1' });
  assert.equal(options.applies, 'live');
  assert.equal(options.custom_models, false);
  assert.deepEqual(options.providers.map(p => [p.id, p.usable]), [['provider-a', true], ['provider-b', false]], 'a hidden id is left out');
  assert.equal(options.providers[0].setup, undefined);
  assert.match(options.providers[1].setup, /missing auth/);
  assert.match(options.providers[1].setup, /openclaw models auth login --provider provider-b --agent scout/);
});

test('models list one model provider with its names, cut to the bound', async () => {
  const listed = await harness().request({ action: 'models', provider: 'provider-a' });
  assert.deepEqual(listed.models, [{ id: 'model-1', label: 'model-1' }, { id: 'model-2', label: 'Model Two' }]);
  assert.equal(listed.limited, false);
  const many = Array.from({ length: MAX_MODELS + 10 }, (_, i) => `m-${String(i).padStart(4, '0')}`);
  const long = await harness({ models: many }).request({ action: 'models', provider: 'provider-a' });
  assert.ok(long.models.length <= MAX_MODELS);
  assert.equal(long.limited, true);
  await assert.rejects(harness().request({ action: 'models', provider: 'provider-z' }), code('not_found'));
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

test('an agent on the shared default keeps that default\'s fallbacks', async () => {
  const h = harness({ config: { agents: { defaults: { model: { primary: 'provider-a/model-1', fallbacks: ['provider-b/b-1'] } }, entries: { scout: {} } } } });
  const { revision } = await h.request({ action: 'options' });
  await h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision });
  assert.deepEqual(h.config().agents.entries.scout.model, { primary: 'provider-a/model-2', fallbacks: ['provider-b/b-1'] });
});

test('a config with the older agents.list is read and written there, its roster kept', async () => {
  const list = [{ id: 'main', workspace: '/w/main' }, { id: 'scout', workspace: '/w/scout', model: { primary: 'provider-a/model-1' } }];
  const h = harness({ config: { agents: { list } } });
  const options = await h.request({ action: 'options' });
  assert.deepEqual(options.current, { provider: 'provider-a', model: 'model-1' });
  await h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision: options.revision });
  const agents = h.config().agents;
  assert.equal(agents.entries, undefined, 'no second roster');
  assert.deepEqual(agents.list.map(a => a.id), ['main', 'scout']);
  assert.deepEqual(agentEntry(h.config(), 'scout'), { id: 'scout', workspace: '/w/scout', model: { primary: 'provider-a/model-2' } });
  // An agent missing from the list is not added there.
  const missing = harness({ config: { agents: { list: [{ id: 'main' }] } } });
  const { revision } = await missing.request({ action: 'options' });
  await assert.rejects(missing.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('unsupported'));
  assert.deepEqual(missing.config().agents.list, [{ id: 'main' }]);
});

test('set is refused for a stale revision, a model provider not set up, or a model OpenClaw does not list', async () => {
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  await assert.rejects(h.request({ action: 'set', provider: 'provider-b', model: 'b-1', revision }), code('not_allowed'));
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'nope', revision }), code('not_found'));
  h.change({ agents: { defaults: { model: { primary: 'provider-a/model-2' } }, entries: { scout: {} } } });
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('conflict'));
  assert.equal(h.writes.length, 0);
});

test('a change made while the write prepares is refused on the draft, nothing changed', async () => {
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  h.beforeMutate(() => h.change({ agents: { defaults: { model: { primary: 'provider-b/b-1' } }, entries: { scout: {} } } }));
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('conflict'));
  assert.equal(agentEntry(h.config(), 'scout').model, undefined);
});

test('a read that fails says so and changed nothing; a write that fails is unknown', async () => {
  const broken = harness({ catalogue: async () => { throw new TypeError('catalogue moved'); } });
  await assert.rejects(broken.request({ action: 'options' }), code('agent_unavailable'));
  const shapeless = harness({ catalogue: async () => ({ providers: [], byProvider: {} }) });
  await assert.rejects(shapeless.request({ action: 'options' }), code('unsupported'));
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  h.failWrite(new Error('config validation refused'));
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('unknown'));
});

test('a change made but not confirmed is never answered as safe to retry', async () => {
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  h.afterWrite(() => h.revoke());
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('unknown'));
  assert.equal(h.writes.length, 1);
});

test('a saved model that does not read back is unknown, not assumed', async () => {
  const h = harness();
  const { revision } = await h.request({ action: 'options' });
  // The write lands under another model provider than asked.
  h.settings.runtime().config.mutateConfigFile = async () => ({ nextConfig: { agents: { entries: { scout: { model: { primary: 'provider-b/b-1' } } } } } });
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision }), code('unknown'));
});

test('a write OpenClaw follows with a restart says so', async () => {
  const h = harness({ requiresRestart: true });
  const { revision } = await h.request({ action: 'options' });
  const set = await h.request({ action: 'set', provider: 'provider-a', model: 'model-2', revision });
  assert.equal(set.applies, 'restart');
});

test('a reconfigured account gets no answer', async () => {
  const h = harness();
  h.revoke();
  await assert.rejects(h.request({ action: 'options' }));
  assert.equal(h.replies.length, 0);
});

test('requests are checked before OpenClaw is asked', async () => {
  const h = harness();
  await assert.rejects(h.request({ action: 'set', provider: 'provider-a', model: '', revision: 'r' }), code('bad_message'));
  await assert.rejects(h.request({ action: 'rename' }), code('bad_message'));
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
