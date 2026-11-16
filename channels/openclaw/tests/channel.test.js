import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
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

test('a native dispatch error becomes one correlated reply without leaking diagnostics', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg);
  native.api.channel.inbound.dispatch = async params => {
    const error = new Error('ProcessInspectionError: SENSITIVE_NATIVE_DIAGNOSTIC');
    await params.delivery.onError?.(error, { kind: 'final' });
    await params.delivery.onError?.(error, { kind: 'final' });
    return { queuedFinal: false, counts: { final: 0 } };
  };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const input = message('message.in', { conversation: 'c', person: 'alice', text: 'hello' });
  owner.send(input);
  const reply = await owner.next('message.out');
  assert.equal(reply.reply_to, input.id);
  assert.equal(reply.kind, 'reply');
  assert.match(reply.text, /could not respond/);
  assert.equal(reply.text.includes('SENSITIVE_NATIVE_DIAGNOSTIC'), false);
  await owner.next('ack', input.id);
  assert.equal(channel.running.get(account.accountId).transport.state.outbox.length, 1);
});

test('a thrown native failure produces a visible reply and ends answering without replaying the turn', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg); let calls = 0;
  native.api.channel.inbound.dispatch = async () => {
    calls++;
    throw new Error('codex app-server request timed out: SENSITIVE_NATIVE_DIAGNOSTIC');
  };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  await owner.hello({ capabilities: ['activity'] }); await owner.next('agent.activity');
  const input = message('message.in', { conversation: 'c', person: 'alice', text: 'hello' });
  owner.send(input);
  assert.equal((await owner.next('agent.activity')).doing.length, 1);
  const reply = await owner.next('message.out');
  assert.equal(reply.reply_to, input.id); assert.equal(reply.kind, 'reply');
  assert.match(reply.text, /could not respond/); assert.equal(reply.text.includes('SENSITIVE_NATIVE_DIAGNOSTIC'), false);
  assert.deepEqual((await owner.next('agent.activity')).doing, []);
  await owner.next('error', input.id);
  owner.send(input); await owner.next('error', input.id);
  assert.equal(calls, 1, 'uncertain native work must never be replayed');
  assert.equal(channel.running.get(account.accountId).transport.state.outbox.length, 1);
  assert.equal(owner.pending.some(frame => frame.type === 'ack' && frame.of === input.id), false);
});

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
  assert.throws(() => createChannel().setRuntime({ version: '2026.11.2' }), /matching enclos channel/);
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

test('channel accounts sharing a socket folder get separate state folders by default', () => {
  const account = id => ({ agentId: id, socket: `/sandbox/sockets/${id}.sock`, tokenFile: '/sandbox/token.json', home: `home.lab.${id}` });
  const cfg = { channels: { enclos: { accounts: { first: account('first'), second: account('second') } } } };
  assert.notEqual(resolveAccount(cfg, 'first').stateDir, resolveAccount(cfg, 'second').stateDir);
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
  assert.deepEqual(hello.capabilities, ['typing', 'abort', 'commands', 'tools', 'approval', 'activity']);
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
  const deniedPath = path.join(path.dirname(account.socket), 'denied');
  const requestedPath = path.join(path.dirname(account.socket), 'requested');
  hooks.get('after_tool_call')({ toolName: 'read', toolCallId: 'denied-call', params: { path: deniedPath }, error: 'EPERM: operation not permitted' }, ctx);
  const observed = await owner.next('approval.request');
  assert.deepEqual(observed.access, { kind: 'read', target: deniedPath, private: false });
  let live = true;
  const tool = toolFactory.create({ ...ctx, messageChannel: 'enclos', assertInvocationCurrent() { if (!live) throw new Error('retired invocation'); } });
  assert.equal(toolFactory.create({ sessionKey: 'unrelated', assertInvocationCurrent() {} }), null);
  assert.match(tool.description, /policy request/);
  assert.doesNotMatch(tool.description, /scope/);
  const result = await tool.execute('tool-call', { kind: 'read', target: requestedPath, action: 'Read the requested file' });
  const request = await owner.next('approval.request');
  assert.equal(request.id, result.details.request); assert.equal(result.details.status, 'requested');
  assert.deepEqual(request.access, { kind: 'read', target: requestedPath, private: false });
  assert.equal(channel.running.get('main').transport.state.policyContext, policy.text);
  live = false;
  await assert.rejects(tool.execute('tool-call', { kind: 'read', target: requestedPath, action: 'Read it again' }), /retired invocation/);
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

test('failed native and direct sends remove staged files', async t => {
  const account = accountFixture(t), cfg = configured(account), folder = mediaFolder(account);
  const sdk = {
    mediaRoots: () => [path.dirname(account.socket)],
    loadMedia: async () => ({ buffer: Buffer.from('test'), fileName: 'file.txt', contentType: 'text/plain' }),
  };
  const channel = createChannel(sdk), native = nativeHarness(cfg);
  channel.setRuntime(native.api);
  native.api.channel.inbound.dispatch = params => params.delivery.deliver({ mediaUrl: '/fixture.txt' });
  await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close()); await owner.hello();
  const ctx = { cfg, accountId: 'main', to: 'files', mediaUrl: '/fixture.txt' };
  const fail = () => { assert.equal(readdirSync(folder).length, 1); throw new Error('send refused'); };
  await assert.rejects(channel.plugin.outbound.sendMedia({ ...ctx, onPlatformSendDispatch: fail }), /send refused/);
  assert.deepEqual(readdirSync(folder), []);
  const active = channel.running.get('main');
  active.transport.send = fail;
  const input = message('message.in', { conversation: 'files', person: 'alice', text: 'hello' });
  owner.send(input);
  assert.equal((await owner.next('error', input.id)).code, 'agent_unavailable');
  assert.deepEqual(readdirSync(folder), []);
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

test('native titles and human renames cross the authenticated channel using the exact route', async t => {
  const account = accountFixture(t), cfg = configured(account), native = nativeHarness(cfg), channel = createChannel();
  let row = { sessionId: 'test-owned', updatedAt: 42, autoLabel: 'Native title' }, selected;
  native.api.agent = { session: {
    resolveStorePath: () => '/test-owned/store',
    async getSessionEntryAsync(target) { selected = target; return row; },
    async prepareSessionEntryPatch(params) {
      assert.equal(params.sessionKey, selected.sessionKey); params.authority.assertCurrent();
      row = { ...row, ...await params.prepare(row, { existingEntry: row }) };
      params.authority.assertCurrent(); return row;
    },
  } };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.ok((await owner.hello()).capabilities.includes('titles'));
  const input = message('message.in', { conversation: 'c', person: 'alice', text: 'hello' });
  owner.send(input); await owner.next('ack', input.id);
  assert.equal((await owner.next('conversation.title')).title, 'Native title');
  const rename = message('conversation.rename', { conversation: 'c', title: 'Human title' });
  owner.send(rename); await owner.next('ack', rename.id);
  const titled = await owner.next('conversation.title'); assert.equal(titled.title, 'Human title'); assert.equal(titled.conversation, 'c');
  assert.equal(row.updatedAt, 42); assert.equal(row.label, undefined);
  assert.equal(selected.sessionKey, native.calls.dispatch[0].route.sessionKey);
  assert.equal(selected.agentId, 'main');
});

test('typed abort keeps exact native signals apart and cancels preparation before dispatch', async t => {
  const account = accountFixture(t), cfg = configured(account), native = nativeHarness(cfg), channel = createChannel();
  const signals = new Map(); let release, preparing = false;
  const preparation = new Promise(resolve => { release = resolve; });
  const ingress = native.api.channel.inbound.ingress.resolve;
  native.api.channel.inbound.ingress.resolve = async params => {
    const result = await ingress(params);
    if (params.contextBinding.messageId === 'prepare') { preparing = true; await preparation; }
    return result;
  };
  native.api.channel.inbound.dispatch = async params => {
    signals.set(params.messageId, params.replyOptions.abortSignal);
    await new Promise(resolve => params.replyOptions.abortSignal.addEventListener('abort', resolve, { once: true }));
  };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.ok((await owner.hello()).capabilities.includes('abort'));
  const send = id => owner.send({ ...message('message.in', { conversation: 'c', person: 'alice', text: 'hello' }), id });
  const abort = async (of, conversation = 'c') => {
    const control = message('turn.abort', { of, conversation }); owner.send(control); await owner.next('ack', control.id);
  };
  send('first'); send('second'); await waitFor(() => signals.size === 2);
  await abort('first', 'different'); assert.equal(signals.get('first').aborted, false);
  await abort('first'); await owner.next('ack', 'first'); assert.equal(signals.get('first').aborted, true);
  await abort('first'); assert.equal(signals.get('second').aborted, false);
  await abort('second'); await owner.next('ack', 'second');
  send('prepare'); await waitFor(() => preparing);
  await abort('prepare'); release();
  assert.equal((await owner.next('error', 'prepare')).code, 'agent_unavailable');
  assert.equal(signals.has('prepare'), false);
  send('successor'); await waitFor(() => signals.has('successor'));
  await abort('first'); assert.equal(signals.get('successor').aborted, false);
  await abort('successor'); await owner.next('ack', 'successor');
});

test('answering activity follows native dispatch settlement, survives reconnect and counts overlapping ingresses', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg), pending = new Map();
  native.api.channel.inbound.dispatch = async params => {
    params.assertAuthority();
    await new Promise(resolve => pending.set(params.messageId, { resolve, params }));
  };
  channel.setRuntime(native.api);
  await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  assert.ok((await owner.hello({ capabilities: ['activity'] })).capabilities.includes('activity'));
  assert.deepEqual((await owner.next('agent.activity')).doing, []);
  owner.send(message('message.in', { id: 'active-first', conversation: 'c', person: 'p', text: 'first' }));
  owner.send(message('message.in', { id: 'active-second', conversation: 'c', person: 'p', text: 'second' }));
  await waitFor(() => pending.size === 2);
  assert.deepEqual((await owner.next('agent.activity')).doing, [{ kind: 'answering', conversation: 'c' }]);
  pending.get('active-first').params.dispatcherOptions.onIdle();
  pending.get('active-first').resolve();
  await owner.next('ack', 'active-first');
  assert.equal(owner.pending.some(frame => frame.type === 'agent.activity'), false, 'typing idle and one completion do not clear another ingress');
  await owner.close();
  await waitFor(() => channel.running.get(account.accountId).transport.peer == null);
  const replacement = await bridge(account.socket); t.after(() => replacement.close());
  await replacement.hello({ capabilities: ['activity'] });
  assert.deepEqual((await replacement.next('agent.activity')).doing, [{ kind: 'answering', conversation: 'c' }]);
  pending.get('active-second').resolve();
  const idle = await replacement.next('agent.activity');
  assert.deepEqual(idle.doing, []); assert.equal(idle.since, 0);
  assert.deepEqual(channel.running.get(account.accountId).transport.state.outbox, [], 'activity is transient');
});

test('failed admission never reports answering and failed native dispatch clears it', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg);
  let admitted = false;
  native.api.channel.inbound.ingress.resolve = async () => admitted
    ? { ingress: { admission: 'dispatch' }, senderAccess: { allowed: true }, routeAccess: { allowed: true } }
    : { ingress: { admission: 'deny' } };
  native.api.channel.inbound.dispatch = async () => { throw new Error('native failed'); };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  await owner.hello({ capabilities: ['activity'] }); await owner.next('agent.activity');
  owner.send(message('message.in', { id: 'denied', conversation: 'c', person: 'p', text: 'denied' }));
  await owner.next('error', 'denied');
  assert.equal(owner.pending.some(frame => frame.type === 'agent.activity'), false);
  admitted = true;
  owner.send(message('message.in', { id: 'failed', conversation: 'c', person: 'p', text: 'fails' }));
  assert.equal((await owner.next('agent.activity')).doing.length, 1);
  assert.deepEqual((await owner.next('agent.activity')).doing, []);
  await owner.next('error', 'failed');
});

test('cancellation retains answering until native cleanup finishes and old peers receive no activity', async t => {
  const account = accountFixture(t), cfg = configured(account), channel = createChannel();
  const native = nativeHarness(cfg); let finish, aborted = false;
  native.api.channel.inbound.dispatch = async params => {
    params.replyOptions.abortSignal.addEventListener('abort', () => { aborted = true; }, { once: true });
    await new Promise(resolve => { finish = resolve; });
  };
  channel.setRuntime(native.api); await start(t, channel, cfg, account);
  const owner = await bridge(account.socket); t.after(() => owner.close());
  await owner.hello();
  owner.send(message('message.in', { id: 'cancelled-ingress', conversation: 'c', person: 'p', text: 'wait' }));
  await waitFor(() => finish);
  owner.send(message('turn.abort', { id: 'abort', conversation: 'c', of: 'cancelled-ingress' }));
  await owner.next('ack', 'abort');
  assert.equal(aborted, true);
  assert.equal(owner.pending.some(frame => frame.type === 'agent.activity'), false);
  await owner.close();
  await waitFor(() => channel.running.get(account.accountId).transport.peer == null);
  const replacement = await bridge(account.socket); t.after(() => replacement.close());
  await replacement.hello({ capabilities: ['activity'] });
  assert.equal((await replacement.next('agent.activity')).doing.length, 1, 'an abort acknowledgement is not completed cleanup');
  finish();
  assert.deepEqual((await replacement.next('agent.activity')).doing, []);
});
