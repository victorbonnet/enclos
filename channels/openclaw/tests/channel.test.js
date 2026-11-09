import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createChannel, resolveAccount, sessionPeer, TESTED_OPENCLAW } from '../channel.js';
import { message } from '../protocol.js';
import { accountFixture, bridge, waitFor } from './helpers.js';

function nativeHarness(cfg) {
  const calls = { ingress: [], contexts: [], dispatch: [] };
  const api = { version: TESTED_OPENCLAW, config: { current: () => cfg }, channel: {
    text: { hasControlCommand: text => text.startsWith('/') },
    routing: {
      resolveAgentRoute: ({ accountId }) => ({ agentId: cfg.channels.enclos.accounts[accountId].agentId, matchedBy: 'binding.account' }),
      buildAgentSessionKey: ({ agentId, accountId, peer }) => `agent:${agentId}:enclos:${accountId}:direct:${peer.id}`,
    },
    inbound: {
      ingress: { async resolve(params) {
        calls.ingress.push(params);
        return { ingress: { admission: 'dispatch' }, senderAccess: { allowed: true }, routeAccess: { allowed: true },
          activationAccess: { shouldSkip: false }, commandAccess: { authorized: true } };
      } },
      buildContext(params) { calls.contexts.push(params); return params; },
      async dispatch(params) {
        params.assertAuthority(); calls.dispatch.push(params);
        await params.delivery.deliver({ text: 'native reply' });
        return { dispatched: true };
      },
    },
  } };
  return { api, calls };
}

function configured(...accounts) {
  return { channels: { enclos: { accounts: Object.fromEntries(accounts.map(a => [a.accountId, a])) } },
    bindings: accounts.map(a => ({ agentId: a.agentId, match: { channel: 'enclos', accountId: a.accountId } })) };
}

async function start(t, channel, cfg, account) {
  const controller = new AbortController();
  const lifetime = channel.plugin.gateway.startAccount({ cfg, accountId: account.accountId, abortSignal: controller.signal, setStatus() {} });
  t.after(async () => { controller.abort(); await lifetime; });
  await waitFor(() => existsSync(account.socket));
  return controller;
}

test('only the tested native version is accepted and accounts are explicit', t => {
  const one = accountFixture(t, 'main'), two = accountFixture(t, 'scout');
  const cfg = configured(one, two);
  assert.throws(() => createChannel().setRuntime({ version: '2026.11.3' }), /matching enclos channel/);
  assert.throws(() => resolveAccount(cfg), /explicit configured account/);
  assert.equal(resolveAccount(configured(one)).agentId, 'main');
  assert.equal(resolveAccount(cfg, 'scout').tokenFile, two.tokenFile);
  assert.equal(sessionPeer('conversation-a', 'alice'), sessionPeer('conversation-a', 'alice'));
  assert.notEqual(sessionPeer('conversation-a', 'alice'), sessionPeer('conversation-b', 'alice'));
  assert.notEqual(sessionPeer('conversation-a', 'alice'), sessionPeer('conversation-a', 'bob'));
});

test('native inbound keeps account, conversation, person and group-member contexts separate', async t => {
  const one = accountFixture(t, 'main'), two = accountFixture(t, 'scout');
  const cfg = configured(one, two); const channel = createChannel(); const native = nativeHarness(cfg);
  channel.setRuntime(native.api);
  await start(t, channel, cfg, one); await start(t, channel, cfg, two);
  const first = await bridge(one.socket), second = await bridge(two.socket);
  t.after(() => first.close()); t.after(() => second.close());
  await first.hello(); await second.hello();
  const send = async (owner, conversation) => {
    const input = message('message.in', { conversation, person: 'alice@example.com', text: 'hello' });
    owner.send(input); await owner.next('ack', input.id);
    const reply = await owner.next('message.out'); assert.equal(reply.reply_to, input.id);
    return native.calls.dispatch.at(-1).route.sessionKey;
  };
  const a = await send(first, 'direct-a'), b = await send(first, 'direct-b');
  assert.notEqual(a, b); assert.equal(await send(first, 'direct-a'), a);
  const mainGroup = await send(first, 'group-same-id'), scoutGroup = await send(second, 'group-same-id');
  assert.notEqual(mainGroup, scoutGroup);
  assert.ok(native.calls.contexts.every(c => c.conversation.kind === 'direct'));
  assert.ok(native.calls.contexts.every(c => c.command.kind === 'normal' && c.command.authorized === false));
  assert.ok(native.calls.contexts.every(c => c.channelIngress.ingress.admission === 'dispatch'));
  assert.equal(native.calls.ingress[0].contextBinding.sessionKey, a);
  assert.equal(native.calls.ingress[0].contextBinding.nativeChannelId, 'direct-a');
  const unsolicited = await channel.plugin.outbound.sendText({ cfg, accountId: 'main', to: 'home', text: 'scheduled output' });
  const notice = await first.next('message.out');
  assert.equal(notice.id, unsolicited.messageId); assert.equal(notice.conversation, one.home); assert.equal(notice.kind, 'notify');
});

test('disabled or rebound account authority is checked after awaited native preparation', async t => {
  const account = accountFixture(t); const cfg = configured(account); const channel = createChannel();
  const native = nativeHarness(cfg); let release;
  const blocker = new Promise(resolve => { release = resolve; });
  const resolve = native.api.channel.inbound.ingress.resolve;
  native.api.channel.inbound.ingress.resolve = async params => { const result = await resolve(params); await blocker; return result; };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const input = message('message.in', { conversation: 'c', person: 'alice', text: 'hello' });
  owner.send(input); await waitFor(() => native.calls.ingress.length === 1);
  cfg.channels.enclos.accounts.main.enabled = false; release();
  assert.equal((await owner.next('error', input.id)).code, 'agent_unavailable');
  assert.equal(native.calls.dispatch.length, 0);
  await assert.rejects(channel.plugin.outbound.sendText({ cfg, accountId: 'main', to: 'home', text: 'must not send' }));
});

test('first-use Home has a native route before a person speaks and retains it afterwards', async t => {
  const account = accountFixture(t); const cfg = configured(account); const channel = createChannel(); const native = nativeHarness(cfg);
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const before = await channel.plugin.messaging.resolveOutboundSessionRoute({ cfg, accountId: 'main', agentId: 'main', target: 'home' });
  assert.ok(before.sessionKey.includes(':enclos:main:direct:'));
  assert.equal(before.from, 'enclos:main');
  assert.equal(await channel.plugin.messaging.resolveOutboundSessionRoute({ cfg, accountId: 'main', agentId: 'scout', target: 'home' }), null);
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const input = message('message.in', { conversation: account.home, person: 'alice', text: 'hello Home' });
  owner.send(input); await owner.next('ack', input.id);
  assert.equal(native.calls.dispatch.at(-1).route.sessionKey, before.sessionKey);
  const after = await channel.plugin.messaging.resolveOutboundSessionRoute({ cfg, accountId: 'main', agentId: 'main', target: 'home' });
  assert.equal(after.sessionKey, before.sessionKey); assert.equal(after.from, 'alice');
  const stranger = message('message.in', { conversation: account.home, person: 'bob', text: 'different owner' });
  owner.send(stranger); assert.equal((await owner.next('error', stranger.id)).code, 'not_allowed');
});

test('missing native binding and unsupported controls have no hidden fallback dispatch', async t => {
  const account = accountFixture(t); const cfg = configured(account); const channel = createChannel(); const native = nativeHarness(cfg);
  native.api.channel.routing.resolveAgentRoute = () => ({ agentId: 'main', matchedBy: 'default' });
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const input = message('message.in', { conversation: 'c', person: 'p', text: 'hello' });
  owner.send(input); await owner.next('error', input.id);
  const control = message('conversation.rename', { conversation: 'c', title: 'new' });
  owner.send(control); assert.equal((await owner.next('error', control.id)).code, 'unsupported');
  assert.equal(native.calls.dispatch.length, 0);
});
