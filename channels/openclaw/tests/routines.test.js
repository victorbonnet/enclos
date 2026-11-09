import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RoutineInventory } from '../routines.js';
import { message } from '../protocol.js';

const account = { agentId: 'main', accountId: 'enclos-main' };
function job(id = 'one', extra = {}) {
  return { id, agentId: 'main', name: 'Native fixture', enabled: true,
    schedule: { kind: 'cron', expr: '0 9 * * *', tz: 'Europe/Paris' },
    payload: { kind: 'agentTurn', message: 'Inspect the fixture.', model: 'openai/example' },
    delivery: { mode: 'announce', channel: 'enclos', accountId: account.accountId, to: 'home.lab.main' },
    state: { nextRunAtMs: 1900000000000, lastRunStatus: 'ok' }, ...extra };
}
function harness(jobs = [job()]) {
  const inventory = new RoutineInventory({ timezone: () => 'Europe/Paris' });
  const calls = [], replies = [];
  const cron = { async list(opts) { calls.push(opts); return jobs; }, async isEnabled() { return true; },
    add() { throw new Error('must not mutate'); }, update() { throw new Error('must not mutate'); }, remove() { throw new Error('must not mutate'); }, enqueueRun() { throw new Error('must not run'); } };
  let current = true;
  const context = { getCron: () => cron };
  inventory.start(context);
  return { inventory, cron, calls, replies, context, revoke() { current = false; },
    async request(fields = {}) {
      await inventory.handle(message('routine.request', { action: 'list', allowed_deliveries: ['home.lab.main'], ...fields }),
        { account, assertCurrent() { if (!current) throw new Error('account changed'); }, write(reply) { replies.push(reply); } });
      return replies.at(-1);
    } };
}
const code = expected => error => error.code === expected;

test('only a started public service lease advertises routines', async () => {
  const inventory = new RoutineInventory(); let service;
  assert.equal(inventory.available(), false);
  inventory.register({ registerService(value) { service = value; } });
  assert.equal(service.id, 'enclos-routines');
  await service.start({ getCron: () => ({ list() {} }) });
  assert.equal(inventory.available(), true);
  await service.stop();
  assert.equal(inventory.available(), false);
  await assert.rejects(inventory.handle({ id: 'request', action: 'list' }, { account, assertCurrent() {}, write() { assert.fail(); } }), code('agent_unavailable'));
});

test('inventory filters exact agent ownership and returns native observations read-only', async () => {
  const h = harness([job(), job('other', { agentId: 'scout' }), job('implicit', { agentId: undefined })]);
  const response = await h.request();
  assert.deepEqual(h.calls, [{ includeDisabled: true }]);
  assert.deepEqual(response.options.operations, ['get']);
  assert.deepEqual(response.options.features, []);
  assert.equal(response.options.timezone, 'Europe/Paris');
  assert.deepEqual(response.routines.map(r => r.id), ['one']);
  assert.equal(response.routines[0].editable, false);
  assert.equal(response.routines[0].next_run_at, new Date(1900000000000).toISOString());
  assert.equal(response.routines[0].delivery_label, 'home.lab.main');
  const full = await h.request({ action: 'get', routine: 'one' });
  assert.equal(full.routine.definition.prompt, 'Inspect the fixture.');
  assert.equal(full.routine.definition.model, 'openai/example');
  assert.equal(full.routine.definition.delivery, 'home.lab.main');
  await assert.rejects(h.request({ action: 'get', routine: 'other' }), code('not_found'));
  await assert.rejects(h.request({ action: 'get' }), code('bad_message'));
});

test('every native write is refused before any scheduler access', async () => {
  const h = harness();
  for (const action of ['create', 'update', 'delete', 'set_enabled', 'run']) {
    await assert.rejects(h.request({ action, routine: 'one', revision: 'anything' }), code('unsupported'));
  }
  assert.equal(h.calls.length, 0);
  assert.equal(h.replies.length, 0);
});

test('stopped, replaced and revoked leases cannot publish an awaited inventory', async () => {
  for (const invalidate of [h => h.inventory.stop(), h => h.inventory.start(h.context), h => { h.context.getCron = () => ({}); }, h => h.revoke()]) {
    const h = harness(); let release;
    h.cron.list = () => new Promise(resolve => { release = resolve; });
    const request = h.request(); invalidate(h); release([job()]);
    await assert.rejects(request, code('agent_unavailable'));
    assert.equal(h.replies.length, 0);
  }
});

test('definition pagination stays valid across execution progress but conflicts on definition changes', async () => {
  const jobs = Array.from({ length: 31 }, (_, i) => job(`routine-${String(i).padStart(2, '0')}`));
  const h = harness(jobs), first = await h.request();
  assert.equal(first.routines.length, 25);
  assert.ok(first.next_cursor);
  jobs[0].state.lastRunAtMs = 1800000000000;
  jobs[0].updatedAtMs = 1800000000000;
  const refreshed = await h.request();
  assert.equal(refreshed.routines[0].revision, first.routines[0].revision);
  assert.equal((await h.request({ cursor: first.next_cursor })).routines.length, 6);
  jobs[0].payload.message = 'A changed native definition';
  await assert.rejects(h.request({ cursor: first.next_cursor }), code('conflict'));
});

test('native intervals, one-time instants and disabled scheduler status stay faithful', async () => {
  const h = harness([job('interval', { schedule: { kind: 'every', everyMs: 3600000, anchorMs: 1500000000000 } }),
    job('once', { enabled: false, schedule: { kind: 'at', at: '2027-01-01T09:00:00+01:00' } })]);
  h.cron.isEnabled = async () => false;
  const response = await h.request();
  assert.deepEqual(response.routines[0].schedule, { kind: 'interval', minutes: 60 });
  assert.equal(response.routines[0].state, 'paused');
  assert.deepEqual(response.routines[1].schedule, { kind: 'once', at: '2027-01-01T09:00:00+01:00' });
  assert.equal(response.routines[1].state, undefined);
});

test('unsupported native schedules and per-job time zones fail explicitly', async () => {
  for (const schedule of [{ kind: 'cron', expr: '0 9 * * *', tz: 'America/New_York' }, { kind: 'every', everyMs: 1500 }, { kind: 'event', source: 'native-plugin' }]) {
    await assert.rejects(harness([job('one', { schedule })]).request(), code('unsupported'));
  }
});

test('external native delivery and unknown fields are observed without rewriting them', async () => {
  const source = job('external', { delivery: { mode: 'announce', channel: 'telegram', accountId: 'other', to: 'private-destination' }, nativeExtension: { keep: true } });
  const before = structuredClone(source), h = harness([source]);
  const response = await h.request({ action: 'get', routine: 'external' });
  assert.equal(response.routine.delivery_label, 'telegram · native delivery');
  assert.equal(response.routine.definition.delivery, undefined);
  assert.equal(response.routine.editable, false);
  assert.deepEqual(source, before);
});

test('incomplete native prompt or fields cannot become a truncated full definition', async () => {
  for (const extra of [{ payload: { kind: 'agentTurn' } }, { payload: { kind: 'agentTurn', message: 'x'.repeat(8193) } }, { name: 'x'.repeat(513) }]) {
    const h = harness([job('one', extra)]);
    assert.equal((await h.request()).routines.length, 1);
    await assert.rejects(h.request({ action: 'get', routine: 'one' }), code('unsupported'));
  }
});

test('bounded pages fit the bridge frame and oversized native inventory is refused', async () => {
  const jobs = Array.from({ length: 26 }, (_, i) => job(`r-${i}`, { name: '🙂'.repeat(512), payload: { kind: 'agentTurn', message: '🙂'.repeat(2048) }, state: { lastError: '🙂'.repeat(512) } }));
  const response = await harness(jobs).request();
  assert.ok(Buffer.byteLength(JSON.stringify(response)) <= 44 * 1024);
  assert.ok(response.next_cursor);
  await assert.rejects(harness(Array.from({ length: 2049 }, (_, i) => job(`r-${i}`))).request(), code('unsupported'));
});
