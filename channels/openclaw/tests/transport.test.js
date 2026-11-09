import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { ChannelTransport } from '../transport.js';
import { message } from '../protocol.js';
import { accountFixture, bridge, waitFor } from './helpers.js';

test('only one authenticated bridge connects and failed authentication is silent', async t => {
  const account = accountFixture(t);
  const channel = new ChannelTransport(account, { onMessage: async () => {} });
  await channel.start(); t.after(() => channel.close());
  const bad = await bridge(account.socket);
  bad.send(message('hello', { token: 'wrong' }));
  await once(bad.peer, 'close');
  assert.deepEqual(bad.pending, []);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.deepEqual((await owner.hello()).capabilities, []);
  const other = await bridge(account.socket);
  await once(other.peer, 'close');
  assert.deepEqual(other.pending, []);
  writeFileSync(account.tokenFile, JSON.stringify({ MOBILE_APP_TOKEN: 'rotated-only-for-tests' }), { mode: 0o600 });
  owner.send(message('ack', { of: 'none' }));
  await once(owner.peer, 'close');
});

test('outbound ids and order survive disconnection and restart until acknowledgement', async t => {
  const account = accountFixture(t);
  let channel = new ChannelTransport(account, { onMessage: async () => {} });
  const first = channel.send('c1', 'a scheduled answer');
  const second = channel.send('c2', 'a reply', { replyTo: 'incoming-id' });
  await channel.start();
  let owner = await bridge(account.socket);
  await owner.hello({ home: 'home.lab.main' });
  assert.equal((await owner.next('message.out')).id, first);
  assert.equal((await owner.next('message.out')).id, second);
  owner.send(message('ack', { of: first }));
  await waitFor(() => JSON.parse(readFileSync(channel.file)).outbox.length === 1);
  await owner.close(); await channel.close();
  channel = new ChannelTransport(account, { onMessage: async () => {} });
  await channel.start(); t.after(() => channel.close());
  owner = await bridge(account.socket); t.after(() => owner.close());
  await owner.hello();
  const replay = await owner.next('message.out');
  assert.equal(replay.id, second); assert.equal(replay.reply_to, 'incoming-id');
  assert.equal(replay.kind, 'reply');
});

test('ingress deduplication, content fencing and person ownership persist across restart', async t => {
  const account = accountFixture(t); let calls = 0;
  let channel = new ChannelTransport(account, { onMessage: async incoming => { calls++; channel.send(incoming.conversation, 'done', { replyTo: incoming.id }); } });
  await channel.start();
  let owner = await bridge(account.socket); await owner.hello();
  const incoming = message('message.in', { conversation: '__proto__', person: 'alice@example.com', text: 'hello' });
  owner.send(incoming); await owner.next('ack', incoming.id);
  owner.send(incoming); await owner.next('ack', incoming.id);
  assert.equal(calls, 1);
  const different = { ...incoming, text: 'different' }; owner.send(different);
  assert.equal((await owner.next('error', incoming.id)).code, 'conflict');
  const intruder = { ...incoming, id: 'new-id', person: 'bob@example.com' }; owner.send(intruder);
  assert.equal((await owner.next('error', intruder.id)).code, 'not_allowed');
  assert.equal(calls, 1);
  await owner.close(); await channel.close();
  channel = new ChannelTransport(account, { onMessage: async () => { calls++; } });
  await channel.start(); t.after(() => channel.close());
  owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  owner.send(incoming); await owner.next('ack', incoming.id);
  assert.equal(calls, 1);
});

test('an interrupted native delivery is never automatically executed again', async t => {
  const account = accountFixture(t); let calls = 0;
  let channel = new ChannelTransport(account, { onMessage: async () => { calls++; throw new Error('native completion unknown'); } });
  await channel.start();
  let owner = await bridge(account.socket); await owner.hello();
  const incoming = message('message.in', { conversation: 'c', person: 'alice', text: 'perform work' });
  owner.send(incoming); assert.equal((await owner.next('error', incoming.id)).code, 'agent_unavailable');
  await owner.close(); await channel.close();
  channel = new ChannelTransport(account, { onMessage: async () => { calls++; } });
  await channel.start(); t.after(() => channel.close());
  owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  owner.send(incoming); assert.equal((await owner.next('error', incoming.id)).code, 'agent_unavailable');
  assert.equal(calls, 1);
});

test('a concurrent replay shares its existing dispatch instead of starting another', async t => {
  const account = accountFixture(t); let release; let calls = 0;
  const blocked = new Promise(resolve => { release = resolve; });
  const channel = new ChannelTransport(account, { onMessage: async () => { calls++; await blocked; } });
  await channel.start(); t.after(() => channel.close());
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const incoming = message('message.in', { conversation: 'c', person: 'p', text: 'hello' });
  owner.send(incoming); owner.send(incoming);
  await waitFor(() => calls === 1); release();
  await owner.next('ack', incoming.id); await owner.next('ack', incoming.id);
  assert.equal(calls, 1);
});

test('a damaged route cannot collapse a conversation into a native default session', t => {
  const account = accountFixture(t);
  mkdirSync(account.stateDir, { mode: 0o700 });
  writeFileSync(path.join(account.stateDir, 'state.json'), JSON.stringify({ v: 1, outbox: [], receipts: {}, routes: {
    conversation: { person: 'alice', peer: 'not-a-valid-route' },
  } }));
  assert.throws(() => new ChannelTransport(account, { onMessage: async () => {} }), /invalid enclos channel conversation route/);
});
