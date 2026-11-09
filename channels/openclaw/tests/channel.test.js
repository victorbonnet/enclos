import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { createChannel, resolveAccount, sessionPeer, TESTED_OPENCLAW } from '../channel.js';
import { message } from '../protocol.js';
import { mediaFolder } from '../media.js';
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

test('a native service-backed routine response is live, agent-bound and read-only', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg); let service;
  channel.setRuntime(native.api);
  channel.registerFull({ registerService(value) { service = value; } });
  const job = { id: 'native-fixture', agentId: account.agentId, name: 'Fixture', enabled: false,
    schedule: { kind: 'every', everyMs: 3600000 }, payload: { kind: 'agentTurn', message: 'Read this native fixture.' } };
  const cron = { list: async () => [job], isEnabled: async () => true };
  await service.start({ getCron: () => cron });
  t.after(() => service.stop());
  await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.ok((await owner.hello()).capabilities.includes('routines'));
  const request = message('routine.request', { action: 'list' }); owner.send(request);
  const list = await owner.next('routine.response', request.id);
  assert.deepEqual(list.options.operations, ['get']);
  assert.equal(list.routines[0].editable, false);
  const get = message('routine.request', { action: 'get', routine: job.id }); owner.send(get);
  assert.equal((await owner.next('routine.response', get.id)).routine.definition.prompt, job.payload.message);
  const remove = message('routine.request', { action: 'delete', routine: job.id, revision: list.routines[0].revision }); owner.send(remove);
  assert.equal((await owner.next('error', remove.id)).code, 'unsupported');
  assert.deepEqual(channel.running.get(account.accountId).transport.state.outbox, []);
});

test('an awaited routine response never moves to a replacement bridge connection', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  channel.setRuntime(nativeHarness(cfg).api); let service, release, entered = false;
  channel.registerFull({ registerService(value) { service = value; } });
  const blocked = new Promise(resolve => { release = resolve; });
  const cron = { async list() { entered = true; await blocked; return []; } };
  await service.start({ getCron: () => cron }); t.after(() => service.stop());
  await start(t, channel, cfg, account);
  const original = await bridge(account.socket); await original.hello();
  const request = message('routine.request', { action: 'list' }); original.send(request);
  await waitFor(() => entered);
  await original.close();
  await waitFor(() => channel.running.get(account.accountId).transport.peer == null);
  const replacement = await bridge(account.socket); t.after(() => replacement.close()); await replacement.hello();
  release();
  await new Promise(setImmediate);
  assert.equal(replacement.pending.some(value => value.type === 'routine.response' || value.of === request.id), false);
  assert.deepEqual(channel.running.get(account.accountId).transport.state.outbox, []);
});

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

test('typing, exact tool events, native commands and policy requests keep their separate contracts', async t => {
  const account = accountFixture(t); const cfg = configured(account);
  const channel = createChannel({ commands: () => [{ name: 'help', description: 'Native help\non one line', acceptsArgs: false }, { name: 'sethome', description: 'excluded' }] });
  const native = nativeHarness(cfg), hooks = new Map(); let toolFactory;
  channel.setRuntime(native.api);
  channel.registerFull({ on(name, callback) { hooks.set(name, callback); }, registerTool(factory) { toolFactory = factory; } });
  const dispatch = native.api.channel.inbound.dispatch;
  native.api.channel.inbound.dispatch = async params => {
    await params.dispatcherOptions.onReplyStart();
    const ctx = { sessionKey: params.route.sessionKey, agentId: 'main', toolCallId: 'native-call' };
    assert.equal(hooks.get('before_tool_call')({ toolName: 'read', params: { path: '/do-not-infer-policy', secret: 'do-not-show' } }, ctx), undefined);
    const result = await dispatch(params);
    hooks.get('after_tool_call')({ toolName: 'read', durationMs: 5 }, ctx);
    await params.dispatcherOptions.onIdle();
    return result;
  };
  await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  const hello = await owner.hello();
  assert.deepEqual(hello.capabilities, ['typing', 'commands', 'tools', 'approval']);
  assert.deepEqual((await owner.next('commands')).commands, [{ name: 'help', description: 'Native help on one line' }]);
  const policy = message('policy.context', { text: 'Sandbox access: read the permitted workspace only.' });
  owner.send(policy); await owner.next('ack', policy.id);
  const input = message('message.in', { conversation: 'c', person: 'alice', text: 'hello' });
  owner.send(input); await owner.next('ack', input.id);
  assert.equal((await owner.next('typing')).on, true);
  const began = await owner.next('tool'), ended = await owner.next('tool');
  assert.equal(began.call, 'native-call'); assert.equal(began.phase, 'start'); assert.equal(began.label, 'read');
  assert.equal(JSON.stringify(began).includes('do-not-show'), false);
  assert.equal(ended.call, began.call); assert.equal(ended.phase, 'end'); assert.equal(ended.ok, true); assert.equal(ended.duration_ms, 5);
  const ctx = { sessionKey: native.calls.dispatch[0].route.sessionKey, agentId: 'main' };
  assert.deepEqual(hooks.get('before_prompt_build')({}, ctx), { prependContext: policy.text });
  assert.equal(hooks.get('before_prompt_build')({}, { ...ctx, agentId: 'scout' }), undefined);
  hooks.get('after_tool_call')({ toolName: 'read', toolCallId: 'denied-call', params: { path: '/tmp/denied' }, error: 'EPERM: operation not permitted' }, ctx);
  const observed = await owner.next('approval.request');
  assert.deepEqual(observed.access, { kind: 'read', target: '/tmp/denied', private: false });
  let live = true;
  const tool = toolFactory.create({ ...ctx, messageChannel: 'enclos', assertInvocationCurrent() { if (!live) throw new Error('retired invocation'); } });
  assert.equal(toolFactory.create({ sessionKey: 'unrelated', assertInvocationCurrent() {} }), null);
  const result = await tool.execute('tool-call', { kind: 'read', target: '/tmp/requested', action: 'Read the requested file' });
  const request = await owner.next('approval.request');
  assert.equal(request.id, result.details.request); assert.equal(result.details.status, 'requested');
  assert.deepEqual(request.access, { kind: 'read', target: '/tmp/requested', private: false });
  assert.equal(channel.running.get('main').transport.state.policyContext, policy.text);
  live = false;
  await assert.rejects(tool.execute('tool-call', { kind: 'read', target: '/tmp/requested', action: 'Read it again' }), /retired invocation/);
});

test('files enter the native context and an HTML artefact leaves through ordinary media', async t => {
  const account = accountFixture(t), cfg = configured(account), folder = path.dirname(account.socket);
  const sdk = { mediaRoots: () => [folder], async loadMedia(url, options) {
    assert.deepEqual(options.localRoots, [folder]);
    return { buffer: readFileSync(url), fileName: path.basename(url), contentType: 'text/html' };
  } };
  const channel = createChannel(sdk), native = nativeHarness(cfg);
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.ok((await owner.hello()).capabilities.includes('attachments'));
  writeFileSync(path.join(mediaFolder(account), 'input.txt'), 'hello file', { mode: 0o600 });
  const input = message('message.in', { conversation: 'files', person: 'alice', text: '', attachments: [{ file: 'input.txt', name: 'input.txt', mime: 'text/plain', size: 10 }] });
  owner.send(input); await owner.next('ack', input.id);
  assert.deepEqual(native.calls.contexts[0].media, [{ path: path.join(mediaFolder(account), 'input.txt'), contentType: 'text/plain', messageId: input.id }]);
  const html = path.join(folder, 'answer.html'); writeFileSync(html, '<!doctype html><p>Static answer</p>');
  await owner.next('message.out');
  await channel.plugin.outbound.sendMedia({ cfg, accountId: 'main', to: 'files', text: 'Open the page', mediaUrl: html });
  const outgoing = await owner.next('message.out');
  assert.equal(outgoing.text, 'Open the page'); assert.equal(outgoing.attachments[0].mime, 'text/html');
  assert.equal(outgoing.attachments[0].name, 'answer.html');
  assert.equal(readFileSync(path.join(mediaFolder(account), outgoing.attachments[0].file), 'utf8'), '<!doctype html><p>Static answer</p>');
});

test('native fallback rendering precedes delivery and rechecks the account after awaiting', async t => {
  const account = accountFixture(t), cfg = configured(account);
  const original = { presentation: { blocks: [{ type: 'text', text: 'Both native questions' }] }, channelData: { askUser: { questionId: 'native-question' } } };
  let release, began = false, wait = false;
  const blocker = new Promise(resolve => { release = resolve; });
  const channel = createChannel({ async renderPayload(payload) {
    assert.equal(payload, original);
    if (wait) { began = true; await blocker; }
    return { ...payload, text: 'Both native questions\n\nAll options' };
  } });
  const native = nativeHarness(cfg);
  native.api.channel.inbound.dispatch = async params => params.delivery.deliver(original);
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  const hello = await owner.hello(); assert.equal(hello.capabilities.includes('questions'), false);
  const first = message('message.in', { conversation: 'questions', person: 'alice', text: 'hello' });
  owner.send(first); await owner.next('ack', first.id);
  const reply = await owner.next('message.out');
  assert.equal(reply.text, 'Both native questions\n\nAll options'); assert.equal(reply.reply_to, first.id);
  owner.send(message('ack', { of: reply.id }));
  await waitFor(() => channel.running.get('main').transport.state.outbox.length === 0);
  wait = true;
  const input = message('message.in', { conversation: 'questions', person: 'alice', text: 'another' });
  owner.send(input); await waitFor(() => began);
  cfg.channels.enclos.accounts.main.enabled = false; release();
  assert.equal((await owner.next('error', input.id)).code, 'agent_unavailable');
  assert.deepEqual(channel.running.get('main').transport.state.outbox, []);
});
