import { createHash } from 'node:crypto';
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

test('a full persisted registry accepts new input and retains recent deduplication across restart', async t => {
  const account = accountFixture(t);
  const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const input = i => message('message.in', { id: `ingress-${i}`, conversation: `chat-${i}`, person: 'alice', text: 'hello' });
  const receipts = Object.fromEntries(Array.from({ length: 10_000 }, (_, i) => {
    const incoming = input(i);
    return [incoming.id, { hash: hash([incoming.conversation, incoming.person, incoming.text]), status: 'received' }];
  }));
  const routes = Object.fromEntries(Array.from({ length: 4096 }, (_, i) => {
    const conversation = `chat-${i}`;
    return [conversation, { person: 'alice', peer: hash([conversation, 'alice']) }];
  }));
  mkdirSync(account.stateDir, { mode: 0o700 });
  writeFileSync(path.join(account.stateDir, 'state.json'), JSON.stringify({ v: 1, outbox: [], receipts, routes }));
  const seen = [];
  const onMessage = async incoming => seen.push(incoming.id);
  let channel = new ChannelTransport(account, { onMessage });
  await channel.accept(input(9999));
  for (const i of [10000, 10001, 10002]) await channel.accept(input(i));
  assert.equal(Object.keys(channel.state.receipts).length, 10000);
  assert.equal(Object.keys(channel.state.routes).length, 4096);
  assert.equal(channel.state.receipts['ingress-0'], undefined);
  assert.equal(channel.state.routes['chat-0'], undefined);
  channel = new ChannelTransport(account, { onMessage });
  await channel.accept(input(9999));
  await channel.accept(input(10002));
  assert.deepEqual(seen, ['ingress-10000', 'ingress-10001', 'ingress-10002']);
  const original = routes['chat-0'];
  assert.deepEqual(channel.route('chat-0', 'alice').peer, original.peer);
});

test('only new ingress gets the busy error while eight native deliveries are in flight', async t => {
  const account = accountFixture(t);
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const channel = new ChannelTransport(account, { onMessage: () => blocked });
  const input = () => message('message.in', { conversation: 'chat', person: 'alice', text: 'hello' });
  const pending = Array.from({ length: 8 }, () => channel.accept(input()));
  try {
    await assert.rejects(channel.accept(input()), { code: 'agent_unavailable', message: /agent is busy/ });
  } finally {
    release();
    await Promise.all(pending);
  }
});
