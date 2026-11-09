import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNativeTitles } from '../native-titles.js';

function fixture(t) {
  const rows = new Map([['session:c', { sessionId: 'physical-c', updatedAt: 42, autoLabel: 'Native generated title' }]]);
  const cfg = { session: { store: '/test-owned/store' } }, outbox = [], writes = [];
  let listener, current = true, closed = false;
  const runtime = { agent: { session: {
    resolveStorePath: value => value,
    async getSessionEntryAsync({ sessionKey }) { return rows.get(sessionKey); },
    async prepareSessionEntryPatch(params) {
      writes.push(params); params.authority.assertCurrent();
      const entry = rows.get(params.sessionKey);
      const patch = await params.prepare(entry ?? {}, { existingEntry: entry });
      params.authority.assertCurrent();
      if (!entry || !patch) return null;
      if (patch.displayName === 'Rejected title') throw new Error('native snapshot conflict');
      const next = { ...entry, ...patch }; rows.set(params.sessionKey, next); return next;
    },
  } }, gateway: { subscribeSessionChanges(value) { listener = value; return () => { closed = true; }; } } };
  const account = { agentId: 'main' }, transport = { state: { routes: { c: { person: 'alice' } } }, enqueue: frame => outbox.push(frame) };
  const options = { currentConfig: () => cfg, assertCurrent() { if (!current) throw new Error('retired account'); }, sessionKeyFor: c => c === 'c' ? 'session:c' : undefined };
  const titles = createNativeTitles(runtime, account, transport, options); t.after(() => titles.close());
  return { runtime, cfg, rows, outbox, writes, titles, event: event => listener(event), retire: () => { current = false; }, isClosed: () => closed };
}

test('native title observation retains native text and keyed ownership without changing activity', async t => {
  const f = fixture(t); assert.equal(f.titles.available, true);
  await f.titles.refresh('c'); await f.titles.refresh('c');
  assert.deepEqual(f.outbox.map(m => [m.type, m.conversation, m.title]), [['conversation.title', 'c', 'Native generated title']]);
  f.rows.set('session:c', { ...f.rows.get('session:c'), label: 'Human title' });
  f.event({ sessionKey: 'session:c', agentId: 'scout' });
  assert.equal(f.outbox.length, 1);
  f.event({ sessionKey: 'session:c', agentId: 'main' }); await f.titles.refresh('c');
  assert.equal(f.outbox.at(-1).title, 'Human title');
  assert.equal(f.rows.get('session:c').updatedAt, 42); assert.equal(f.writes.length, 0);
  f.titles.close(); assert.equal(f.isClosed(), true);
});

test('human rename uses a guarded native prepared patch and clearing restores the native title', async t => {
  const f = fixture(t);
  assert.equal(await f.titles.handleControl({ type: 'policy.context' }), false);
  await f.titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: '  Human title  ' });
  assert.equal(f.rows.get('session:c').displayName, 'Human title');
  assert.equal(f.writes[0].preserveActivity, true); assert.equal(f.writes[0].requireWriteSuccess, true);
  assert.equal(f.outbox.at(-1).title, 'Human title');
  await f.titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: '' });
  assert.equal(f.rows.get('session:c').displayName, undefined); assert.equal(f.outbox.at(-1).title, 'Native generated title');
  await f.titles.handleControl({ type: 'conversation.rename', conversation: 'unused', title: 'Name before use' });
  assert.equal(f.writes.length, 2);
  await assert.rejects(f.titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: 'Rejected title' }), error => error.code === 'conflict');
  assert.equal(f.rows.get('session:c').displayName, undefined);
});

test('native title reads and mutations retain authority across asynchronous preparation', async t => {
  const f = fixture(t); let release, began = false;
  const blocker = new Promise(resolve => { release = resolve; });
  f.runtime.agent.session.getSessionEntryAsync = async () => { began = true; await blocker; return { label: 'Stale native text' }; };
  const reading = f.titles.refresh('c'); assert.equal(began, true); f.retire(); release(); await reading;
  assert.equal(f.outbox.length, 0);
  await assert.rejects(f.titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: 'No longer allowed' }), /retired account/);
  assert.equal(f.writes.length, 0);
});

test('unsupported session APIs keep title capability unavailable', () => {
  const titles = createNativeTitles({}, {}, {}, {});
  assert.equal(titles.available, false);
});
