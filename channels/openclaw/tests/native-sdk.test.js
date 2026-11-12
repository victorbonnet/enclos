import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createChannel, sessionPeer, TESTED_OPENCLAW } from '../channel.js';
import { commandCatalog } from '../features.js';
import { stageMedia } from '../media.js';
import { createNativeTitles } from '../native-titles.js';
import { createNativeApprovals } from '../native-approvals.js';
import { message } from '../protocol.js';
import { accountFixture, bridge, waitFor } from './helpers.js';

const installed = process.env.ENCLOS_OPENCLAW_PACKAGE;
// Native database helpers also own a shared schema/lease registry. Select a
// disposable native state root before importing any SDK runtime, not just a
// temporary session-store filename.
if (installed) {
  const state = mkdtempSync(path.join(tmpdir(), 'enclos-native-sdk-'));
  process.env.OPENCLAW_STATE_DIR = state;
  process.env.OPENCLAW_CONFIG_PATH = path.join(state, 'openclaw.json');
  after(() => rmSync(state, { recursive: true, force: true }));
}
test('the installed public SDK registers the package and builds isolated session keys', { skip: !installed }, async () => {
  assert.equal(JSON.parse(readFileSync(path.join(installed, 'package.json'))).version, TESTED_OPENCLAW);
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/channel-core.js')));
  const routing = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/routing.js')));
  const channel = createChannel();
  const entry = sdk.defineChannelPluginEntry({ id: 'enclos', name: 'enclos app', description: 'enclos',
    plugin: channel.plugin, setRuntime: channel.setRuntime });
  let registered;
  entry.register({ registrationMode: 'full', runtime: { version: TESTED_OPENCLAW }, registerChannel(value) { registered = value.plugin; } });
  assert.equal(registered.id, 'enclos');
  const route = conversation => routing.buildAgentSessionKey({ agentId: 'main', channel: 'enclos', accountId: 'main',
    peer: { kind: 'direct', id: sessionPeer(conversation, 'alice') }, dmScope: 'per-account-channel-peer' });
  assert.notEqual(route('one'), route('two')); assert.equal(route('one'), route('one'));
  assert.ok(route('one').startsWith('agent:main:enclos:main:direct:'));
  const bound = routing.resolveAgentRoute({ cfg: { agents: { ownership: 'explicit', entries: { main: {} } },
    bindings: [{ agentId: 'main', match: { channel: 'enclos', accountId: 'main' } }] },
    channel: 'enclos', accountId: 'main', peer: { kind: 'direct', id: 'one' }, dmScope: 'per-account-channel-peer' });
  assert.equal(bound.agentId, 'main'); assert.equal(bound.matchedBy, 'binding.account');
  const commands = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/native-command-registry.js')));
  const listed = commandCatalog(commands.listNativeCommandSpecsForConfig, {});
  assert.ok(listed.some(c => c.name === 'help'));
  assert.ok(listed.every(c => c.description.length <= 120 && /^[a-z0-9_-]{1,32}$/.test(c.name)));
});

test('the combined channel registers the native approval context with its actual persisted route', { skip: !installed }, async t => {
  const load = name => import(pathToFileURL(path.join(installed, `dist/plugin-sdk/${name}.js`)));
  const [delivery, handler, contexts, routing] = await Promise.all(['approval-delivery-runtime', 'approval-handler-runtime', 'channel-runtime-context', 'routing'].map(load));
  const account = accountFixture(t), cfg = { channels: { enclos: { accounts: { main: account } } },
    agents: { ownership: 'explicit', entries: { main: {} } }, bindings: [{ agentId: 'main', match: { channel: 'enclos', accountId: 'main' } }] };
  let registration, disposed = false;
  const nativeApprovals = createNativeApprovals({ ...delivery, ...handler, ...contexts,
    resolveApprovalOverGateway() { throw new Error('No decision or Gateway client is needed by this registration fixture'); } });
  const channelRuntime = { routing,
    inbound: { ingress: { resolve: async () => ({ ingress: { admission: 'dispatch' }, senderAccess: { allowed: true }, routeAccess: { allowed: true }, activationAccess: {}, commandAccess: {} }) },
      buildContext: value => value, dispatch: async () => {} },
    runtimeContexts: { register(params) { registration = params; return { dispose() { disposed = true; } }; } } };
  const channel = createChannel({ nativeApprovals });
  assert.equal(channel.plugin.approvalCapability, nativeApprovals.approvalCapability);
  channel.setRuntime({ version: TESTED_OPENCLAW, channel: channelRuntime, config: { current: () => cfg } });
  const abort = new AbortController();
  const lifetime = channel.plugin.gateway.startAccount({ cfg, accountId: 'main', abortSignal: abort.signal, setStatus() {} });
  t.after(async () => { abort.abort(); await lifetime; });
  await waitFor(() => existsSync(account.socket));
  assert.equal(registration.channelId, 'enclos'); assert.equal(registration.accountId, 'main');
  assert.equal(registration.capability, 'approval.native');
  const owner = await bridge(account.socket); t.after(() => owner.close());
  const hello = await owner.hello({ capabilities: ['runtime_approvals', 'runtime_approval_scopes'] });
  assert.ok(hello.capabilities.includes('runtime_approvals')); assert.ok(hello.capabilities.includes('runtime_approval_scopes'));
  assert.equal('token' in channel.running.get('main').transport.bridgeHello, false);
  const input = message('message.in', { conversation: 'exact-conversation', person: 'alice', text: 'Fixture attribution only' });
  owner.send(input); await owner.next('ack', input.id);
  const active = channel.running.get('main');
  const sessionKey = active.sessionKeyFor(input.conversation, input.person);
  const expected = routing.buildAgentSessionKey({ agentId: 'main', channel: 'enclos', accountId: 'main',
    peer: { kind: 'direct', id: active.transport.state.routes[input.conversation].peer }, dmScope: 'per-account-channel-peer' });
  assert.equal(sessionKey, expected);
  const request = { id: 'native-registration-fixture', createdAtMs: Date.now(), expiresAtMs: Date.now() + 60000,
    request: { command: 'fixture only', host: 'gateway', agentId: 'main', turnSourceChannel: 'enclos', turnSourceAccountId: 'main', turnSourceTo: input.conversation, sessionKey } };
  assert.equal(registration.context.target(request)?.person, 'alice');
  assert.equal(registration.context.target({ ...request, request: { ...request.request, sessionKey: `${sessionKey}-other` } }), null);
  const sync = message('question.sync', { questions: ['ordinary-unowned-card', 'oc-exec-unowned-card'] });
  owner.send(sync);
  const expired = await owner.next('question.update');
  assert.equal(expired.question, 'oc-exec-unowned-card'); assert.equal(expired.state, 'expired');
  await owner.next('ack', sync.id);
  // Deliberately retain that structured outbox entry. A downgraded bridge
  // must not receive it during replay or from onHello reconciliation.
  await owner.close(); await waitFor(() => active.transport.peer == null);
  const legacy = await bridge(account.socket); t.after(() => legacy.close());
  const legacyHello = await legacy.hello();
  assert.equal(legacyHello.capabilities.includes('runtime_approvals'), false);
  await new Promise(setImmediate);
  assert.equal(legacy.pending.some(frame => ['question.ask', 'question.update'].includes(frame.type)), false);
  active.transport.assertControlPeer(active.transport.peer);
  writeFileSync(account.tokenFile, JSON.stringify({ MOBILE_APP_TOKEN: 'rotated-fixture-token' }), { mode: 0o600 });
  assert.throws(() => active.transport.assertControlPeer(active.transport.peer), { code: 'agent_unavailable' });
  abort.abort(); await lifetime;
  assert.equal(disposed, true); assert.equal(registration.context.isCurrent(), false);
});

test('the installed scoped media loader preserves HTML and rejects an unrelated local root', { skip: !installed }, async t => {
  const loader = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/web-media.js')));
  const roots = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/media-local-roots.js')));
  const account = accountFixture(t), workspace = path.dirname(account.socket), source = path.join(workspace, 'page.html');
  const html = '<!doctype html><p>Native SDK HTML fixture</p>';
  writeFileSync(source, html);
  const cfg = { agents: { ownership: 'explicit', entries: { main: { workspace } } } };
  const [attachment] = await stageMedia(account, [source], { cfg,
    sdk: { loadMedia: loader.loadWebMediaRaw, mediaRoots: roots.getAgentScopedMediaLocalRoots } });
  assert.equal(attachment.mime, 'text/html'); assert.equal(attachment.name, 'page.html');
  assert.equal(readFileSync(path.join(workspace, 'media', attachment.file), 'utf8'), html);
  const outside = mkdtempSync(path.join(tmpdir(), 'enclos-sdk-outside-')); t.after(() => rmSync(outside, { recursive: true, force: true }));
  const excluded = path.join(outside, 'outside.txt'); writeFileSync(excluded, 'fixture');
  await assert.rejects(loader.loadWebMediaRaw(excluded, { localRoots: [workspace] }));
});

test('the installed native fallback retains every question and respects existing fallback text', { skip: !installed }, async () => {
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/interactive-runtime.js')));
  const id = `ask_${'a'.repeat(32)}`;
  const payload = { channelData: { askUser: { questionId: id } }, presentation: { title: 'Questions for you', blocks: [
    { type: 'text', text: 'First question?' },
    { type: 'buttons', buttons: [
      { label: 'First option', action: { type: 'question', questionId: id, optionValue: 'first' } },
      { label: 'Second option', action: { type: 'question', questionId: id, optionValue: 'second' } },
    ] },
    { type: 'context', text: 'Keep this complete explanation.' },
    { type: 'text', text: 'Second question?' },
    { type: 'select', placeholder: 'Choose several', options: [
      { label: 'Third option', value: 'third' }, { label: 'Fourth option', value: 'fourth' },
    ] },
  ] } };
  const rendered = await sdk.renderPresentationForDelivery({}, payload);
  assert.equal(rendered.presentation, undefined);
  assert.equal(rendered.text, 'Questions for you\n\nFirst question?\n\n- First option\n- Second option\n\nKeep this complete explanation.\n\nSecond question?\n\nChoose several:\n- Third option\n- Fourth option');
  assert.deepEqual(rendered.channelData, payload.channelData);
  assert.equal(rendered.text.includes(id), false);
  const fallback = 'Complete native text, including the native answer instructions.';
  assert.equal((await sdk.renderPresentationForDelivery({}, { ...payload, text: fallback, presentationTextMode: 'fallback' })).text, fallback);
  const credential = { text: 'Never send credentials in chat; open the trusted Control UI.', channelData: payload.channelData };
  assert.equal(await sdk.renderPresentationForDelivery({}, credential), credential);
});

test('installed native session workers read, rename and clear only the selected title', { skip: !installed }, async t => {
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/session-store-runtime.js')));
  const folder = mkdtempSync(path.join(tmpdir(), 'enclos-native-title-')); t.after(() => rmSync(folder, { recursive: true, force: true }));
  const storePath = path.join(folder, 'sessions.json'), sessionKey = 'agent:main:enclos:main:direct:test-owned';
  const entry = { sessionId: '32b35e61-28fb-4b21-bdb5-e8fbb521a18c', updatedAt: 42, autoLabel: 'Native generated title' };
  await sdk.upsertSessionEntry({ agentId: 'main', sessionKey, storePath, entry });
  const outbox = [], transport = { state: { routes: { c: {} } }, enqueue: frame => outbox.push(frame) };
  const titles = createNativeTitles({ agent: { session: { ...sdk, resolveStorePath: () => storePath } } }, { agentId: 'main' }, transport,
    { currentConfig: () => ({}), assertCurrent() {}, sessionKeyFor: c => c === 'c' ? sessionKey : undefined });
  t.after(() => titles.close());
  await titles.refresh('c'); assert.equal(outbox.at(-1).title, 'Native generated title');
  await titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: 'Human title' });
  const named = await sdk.getSessionEntryAsync({ agentId: 'main', sessionKey, storePath, readConsistency: 'latest' });
  assert.equal(named.displayName, 'Human title'); assert.equal(named.label, undefined); assert.equal(named.sessionId, entry.sessionId); assert.equal(named.updatedAt, 42);
  await titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: '' });
  const cleared = await sdk.getSessionEntryAsync({ agentId: 'main', sessionKey, storePath, readConsistency: 'latest' });
  assert.equal(cleared.displayName, undefined); assert.equal(cleared.autoLabel, 'Native generated title'); assert.equal(cleared.updatedAt, 42);
  await sdk.upsertSessionEntry({ agentId: 'main', sessionKey: `${sessionKey}-other`, storePath,
    entry: { sessionId: 'fe9ede27-c8b0-4c1e-bcfc-a79bb6e8d95f', updatedAt: 50, label: 'Addressable native label', displayName: 'Duplicate display title' } });
  await titles.handleControl({ type: 'conversation.rename', conversation: 'c', title: 'Duplicate display title' });
  const duplicate = await sdk.getSessionEntryAsync({ agentId: 'main', sessionKey, storePath, readConsistency: 'latest' });
  assert.equal(duplicate.displayName, 'Duplicate display title'); assert.equal(duplicate.label, undefined);
  assert.equal((await sdk.getSessionEntryAsync({ agentId: 'main', sessionKey: `${sessionKey}-other`, storePath, readConsistency: 'latest' })).label, 'Addressable native label');
});

test('installed native inbound dispatch retains each exact upstream run abort signal', { skip: !installed }, async t => {
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/channel-inbound.js')));
  const folder = mkdtempSync(path.join(tmpdir(), 'enclos-native-abort-'));
  const cfg = { agents: { ownership: 'explicit', entries: { main: { workspace: folder } } }, session: { store: path.join(folder, 'sessions.json') } };
  const seen = new Map(), ended = [], running = [], failures = [];
  const one = new AbortController(), two = new AbortController(), three = new AbortController();
  t.after(async () => { one.abort(); two.abort(); three.abort(); await Promise.allSettled(running); rmSync(folder, { recursive: true, force: true }); });
  const waitSeen = async id => {
    const deadline = Date.now() + 15000;
    while (!seen.has(id)) {
      if (failures.length) throw failures[0];
      if (Date.now() > deadline) throw new Error(`native resolver did not begin: ${id}`);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  };
  const run = (id, controller) => sdk.dispatchChannelInboundTurn({ cfg, channel: 'enclos', accountId: 'main', messageId: id,
    route: { agentId: 'main', sessionKey: 'agent:main:enclos:main:direct:abort-test', dmScope: 'per-account-channel-peer' },
    ctxPayload: { Body: 'test-owned native dispatcher fixture', RawBody: 'test-owned native dispatcher fixture',
      From: 'enclos:alice', To: 'enclos:test', Provider: 'enclos', Surface: 'enclos', ChatType: 'direct',
      AccountId: 'main', MessageSid: id, SenderId: 'alice', SessionKey: 'agent:main:enclos:main:direct:abort-test' },
    replyOptions: { abortSignal: controller.signal },
    replyResolver: async (_ctx, options) => {
      assert.ok(options.abortSignal); seen.set(id, options.abortSignal);
      await new Promise(resolve => {
        if (options.abortSignal.aborted) resolve();
        else options.abortSignal.addEventListener('abort', resolve, { once: true });
      });
      ended.push(id); return undefined;
    },
    delivery: { async deliver() { throw new Error('cancelled native fixture must not deliver output'); } },
  }).catch(error => {
    if (!controller.signal.aborted) failures.push(error);
  });
  const first = run('owned-first', one); running.push(first);
  await waitSeen('owned-first');
  const second = run('owned-second', two); running.push(second);
  // The same native session serializes replies. Cancelling its queued ingress
  // must not select the running ingress by a global session-id lookup.
  two.abort(); await second;
  assert.equal(seen.has('owned-second'), false);
  assert.equal(seen.get('owned-first').aborted, false); assert.equal(ended.includes('owned-first'), false);
  one.abort(); await first;
  assert.equal(seen.get('owned-first').aborted, true); assert.ok(ended.includes('owned-first'));
  const replacement = run('owned-third', three); running.push(replacement);
  await waitSeen('owned-third');
  assert.equal(seen.get('owned-third').aborted, false);
  three.abort(); await replacement;
  assert.ok(ended.includes('owned-third'));
  assert.deepEqual(failures, []);
});
