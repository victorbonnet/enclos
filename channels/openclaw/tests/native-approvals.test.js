import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { createNativeApprovals } from '../native-approvals.js';
import { message } from '../protocol.js';

const modern = { capabilities: ['runtime_approvals', 'runtime_approval_scopes'] };
const account = { accountId: 'main', agentId: 'main' };
const sessionKeyFor = conversation => `agent:main:enclos:main:direct:${conversation}`;
const nativeRequest = (overrides = {}) => ({ id: '7f8f0830-5598-4930-b4a5-2e9cd4effc50', createdAtMs: Date.now() - 100,
  expiresAtMs: Date.now() + 60000, request: { command: 'printf "complete command"', cwd: '/workspace', host: 'gateway',
    agentId: 'main', turnSourceChannel: 'enclos', turnSourceAccountId: 'main', turnSourceTo: 'one',
    sessionKey: sessionKeyFor('one'), ...overrides } });
const viewFor = request => ({ approvalId: request.id, approvalKind: 'exec', phase: 'pending', title: 'Approval required',
  commandText: request.request.command, commandPreview: 'wrong truncated command', cwd: request.request.cwd,
  expiresAtMs: request.expiresAtMs, metadata: [{ label: 'Host', value: request.request.host }], warningText: 'Native warning',
  actions: ['allow-once', 'allow-always', 'deny'].map(decision => ({ decision, label: decision,
    command: `/approve ${request.id} ${decision}`, style: 'secondary' })) });
const outcome = (request, decision = 'allow-once', applied = true) => ({ applied, approval: { id: request.id,
  createdAtMs: request.createdAtMs, expiresAtMs: request.expiresAtMs,
  presentation: { kind: 'exec', commandText: request.request.command }, status: decision === 'deny' ? 'denied' : 'allowed', decision } });

function transport(saved) {
  return { state: saved ? structuredClone(saved) : { routes: { one: { person: 'alice', peer: 'one' }, two: { person: 'alice', peer: 'two' } }, outbox: [] },
    bridgeHello: modern, frames: [], closed: false, save() { this.snapshot = structuredClone(this.state); },
    enqueue(frame) { this.state.outbox.push(frame); this.save(); this.write(frame); return frame.id; },
    write(frame) { this.frames.push(frame); },
    send(conversation, text, fields) { return this.enqueue(message('message.out', { conversation, text, ...fields })); } };
}

function fixture(t, { hello = modern, saved, resolve, timeout, beforeAuthorize } = {}) {
  const wire = transport(saved); wire.bridgeHello = hello;
  let adapter, capability, context, disposed = false, current = true, calls = 0, authorized;
  const sdk = {
    CHANNEL_APPROVAL_NATIVE_RUNTIME_CONTEXT_CAPABILITY: 'approval.native',
    createChannelApprovalNativeRuntimeAdapterAsync(spec) { return adapter = spec; },
    createChannelApprovalCapability(spec) { return capability = spec; },
    registerChannelRuntimeContext(params) { context = params.context; return { dispose() { disposed = true; } }; },
    async resolveApprovalOverGateway(params) {
      calls++;
      assert.equal(params.channel, 'enclos'); assert.equal(params.senderId, 'alice'); assert.equal(params.accountId, 'main');
      assert.equal(params.approvalKind, 'exec');
      if (beforeAuthorize) await beforeAuthorize();
      authorized = (await capability.authorizeActorActionAsync({ ...params, action: 'approve', request: currentNative })).authorized;
      if (!authorized) throw new Error('native reviewer refused this decision');
      return resolve ? resolve(params, currentNative) : outcome(currentNative, params.decision);
    },
  };
  const factory = createNativeApprovals(sdk, { ...(timeout ? { requestTimeoutMs: timeout } : {}) });
  const controller = factory.attach(account, wire, { cfg: {}, channelRuntime: {}, sessionKeyFor,
    assertCurrent() { if (!current) throw new Error('account replaced'); } });
  t.after(() => controller.close());
  let currentNative;
  const base = () => ({ accountId: 'main', cfg: {}, context });
  return { wire, controller, factory, adapter, capability,
    calls: () => calls, authorized: () => authorized, disposed: () => disposed, revoke() { current = false; },
    async deliver(request = nativeRequest(), view = viewFor(request)) {
      currentNative = request;
      const p = { ...base(), request, approvalKind: 'exec', view };
      assert.equal(await adapter.availability.shouldHandle(p), true);
      const pendingPayload = await adapter.presentation.buildPendingPayload(p);
      const plannedTarget = { surface: 'origin', target: { to: request.request.turnSourceTo }, reason: 'preferred' };
      const prepared = await adapter.transport.prepareTarget({ ...p, pendingPayload, plannedTarget });
      const entry = await adapter.transport.deliverPending({ ...p, pendingPayload, plannedTarget, preparedTarget: prepared.target });
      return { request, entry, definition: pendingPayload.definition };
    },
    settle(delivery, state = 'resolved') { return adapter.presentation[state === 'expired' ? 'buildExpiredResult' : 'buildResolvedResult']({ ...base(), request: delivery.request, entry: delivery.entry }); },
  };
}

const answer = (delivery, action = 'once', fields = {}) => message('question.answer', { question: delivery.entry.question,
  conversation: 'one', answer: { kind: 'approval', action }, ...fields });
const last = wire => wire.frames.at(-1);

test('native actions and full command survive; exact canonical resolution alone yields an answer receipt', async t => {
  const f = fixture(t), delivery = await f.deliver();
  assert.deepEqual(f.controller.capabilities(modern), modern.capabilities);
  assert.deepEqual(delivery.definition.approval.actions, ['once', 'always', 'deny']);
  assert.equal(delivery.definition.approval.command, delivery.request.request.command);
  assert.match(delivery.definition.approval.reason, /Native warning/);
  assert.match(delivery.definition.approval.scopes.description, /executable and argument/);
  assert.doesNotMatch(delivery.definition.approval.scopes.description, /session|exact argv/);
  const control = answer(delivery, 'always');
  await f.controller.handleControl(control);
  assert.equal(f.calls(), 1); assert.equal(last(f.wire).state, 'answered');
  assert.equal(last(f.wire).of, control.id); assert.deepEqual(last(f.wire).answer, { kind: 'approval', action: 'always' });
  const receipt = last(f.wire);
  await f.controller.handleControl(control);
  assert.equal(f.calls(), 1); assert.deepEqual(last(f.wire), receipt);
  await assert.rejects(f.controller.handleControl({ ...control, answer: { kind: 'approval', action: 'deny' } }), { code: 'conflict' });
});

test('unoffered session, extra fields, wrong conversation and unbound native commands cannot resolve', async t => {
  const f = fixture(t), delivery = await f.deliver();
  for (const control of [answer(delivery, 'session'), answer(delivery, 'once', { answer: { kind: 'approval', action: 'once', extra: true } })]) {
    await assert.rejects(f.controller.handleControl(control), { code: 'bad_message' });
  }
  await assert.rejects(f.controller.handleControl(answer(delivery, 'once', { conversation: 'two' })), { code: 'conflict' });
  assert.equal((await f.capability.authorizeActorActionAsync({ accountId: 'main', senderId: 'alice', approvalKind: 'exec', request: delivery.request })).authorized, false);
  assert.equal(f.calls(), 0);
});

test('routes require exact account, agent, source, session, owner and local host', async t => {
  const f = fixture(t);
  for (const overrides of [{ agentId: 'other' }, { turnSourceAccountId: 'other' }, { turnSourceChannel: 'telegram' },
    { turnSourceTo: 'unknown' }, { sessionKey: sessionKeyFor('two') }, { turnSourceThreadId: 'thread' },
    { host: 'node', nodeId: 'remote' }, { host: undefined }]) assert.equal(await f.adapter.availability.shouldHandle({ accountId: 'main', approvalKind: 'exec', request: nativeRequest(overrides) }), false);
  f.wire.state.routes.one.person = null;
  assert.equal(await f.adapter.availability.shouldHandle({ accountId: 'main', approvalKind: 'exec', request: nativeRequest() }), false);
});

test('deny-only and once/deny sets are preserved; malformed ordering gets complete native fallback', async t => {
  const f = fixture(t);
  const first = nativeRequest(), view = viewFor(first); view.actions = view.actions.filter(a => a.decision === 'deny');
  const delivery = await f.deliver(first, view);
  assert.deepEqual(delivery.definition.approval.actions, ['deny']);
  await f.controller.handleControl(answer(delivery, 'deny'));
  assert.equal(last(f.wire).state, 'answered');
  const second = nativeRequest(); second.id = 'another';
  const bad = viewFor(second); bad.actions.reverse();
  const unsupported = await f.deliver(second, bad);
  assert.equal(unsupported.entry.fallback, true);
  assert.match(f.wire.frames.filter(frame => frame.type === 'message.out').map(frame => frame.text).join('\n'), /allow-always/);
});

test('legacy or downgraded bridge gets bounded complete text; structured replay is gated', async t => {
  const f = fixture(t, { hello: { capabilities: ['runtime_approvals'] } }), delivery = await f.deliver();
  assert.deepEqual(f.controller.capabilities(f.wire.bridgeHello), []);
  assert.equal(f.wire.frames.some(frame => frame.type === 'question.ask'), false);
  const text = f.wire.frames.map(frame => frame.text ?? '').join('\n');
  assert.ok(text.includes(delivery.request.request.command)); assert.match(text, /allow-once/); assert.match(text, /allow-always/); assert.match(text, /deny/);
  assert.equal(f.controller.canDeliver(message('question.ask', { question: delivery.definition }), f.wire.bridgeHello), false);
  await assert.rejects(f.controller.handleControl(answer(delivery)), { code: 'unsupported' });
  const before = f.wire.frames.length; f.controller.onHello(f.wire.bridgeHello); assert.equal(f.wire.frames.length, before);
  f.wire.bridgeHello = modern; f.controller.onHello(modern);
  assert.equal(last(f.wire).type, 'question.ask');
});

test('an oversized command is never truncated into an actionable card', async t => {
  const f = fixture(t), request = nativeRequest({ command: 'a'.repeat(27000) });
  const delivery = await f.deliver(request);
  assert.equal(delivery.entry.fallback, true);
  assert.equal(f.wire.frames.some(frame => frame.type === 'question.ask'), false);
  const chunks = f.wire.frames.filter(frame => frame.text?.includes('OpenClaw approval (native fallback)'));
  assert.equal(chunks.length, 4); assert.ok(chunks.every(frame => Buffer.byteLength(frame.text) < 8200));
  assert.equal(chunks.map(frame => frame.text.match(/```sh\n([\s\S]*)\n```/)[1]).join(''), request.request.command);
});

test('external native resolution carries no invented action or answer receipt', async t => {
  const f = fixture(t), delivery = await f.deliver();
  await f.settle(delivery);
  assert.equal(last(f.wire).state, 'resolved'); assert.equal(last(f.wire).answer, undefined); assert.equal(last(f.wire).of, undefined);
  await assert.rejects(f.controller.handleControl(answer(delivery)), { code: 'conflict' });
});

test('a competing canonical decision returns neutral state and a conflict, even if its action matches', async t => {
  const f = fixture(t, { resolve: (_params, request) => outcome(request, 'allow-once', false) }), delivery = await f.deliver();
  await f.controller.handleControl(answer(delivery));
  assert.equal(last(f.wire).code, 'conflict');
  const terminal = f.wire.frames.find(frame => frame.type === 'question.update');
  assert.equal(terminal.state, 'resolved'); assert.equal(terminal.answer, undefined); assert.equal(terminal.of, undefined);
});

test('native event racing an exact answer waits for canonical receipt', async t => {
  let release;
  const f = fixture(t, { resolve: (_params, request) => new Promise(resolve => { release = () => resolve(outcome(request)); }) });
  const delivery = await f.deliver(), control = answer(delivery), pending = f.controller.handleControl(control);
  await Promise.resolve(); await f.settle(delivery);
  assert.equal(f.wire.frames.some(frame => frame.type === 'question.update'), false);
  release(); await pending;
  assert.equal(last(f.wire).state, 'answered'); assert.equal(last(f.wire).of, control.id);
});

for (const changed of ['token', 'peer']) test(`a ${changed} revocation during the native read denies commit authorization`, async t => {
  let resume, entered;
  const blocked = new Promise(resolve => { resume = resolve; });
  const observed = new Promise(resolve => { entered = resolve; });
  const initial = { token: 'fixture-token', peer: {} }, current = { ...initial };
  const assertPeer = () => { if (current.token !== initial.token || current.peer !== initial.peer) throw new Error('revoked control peer'); };
  const f = fixture(t, { beforeAuthorize: async () => { entered(); await blocked; } });
  const delivery = await f.deliver(), control = answer(delivery);
  const pending = f.controller.handleControl(control, assertPeer);
  await observed; current[changed] = changed === 'token' ? 'rotated-fixture-token' : {}; resume(); await pending;
  assert.equal(f.authorized(), false);
  assert.equal(f.wire.frames.some(frame => frame.state === 'answered' || frame.of === control.id), false);
  assert.equal(f.wire.state.nativeApprovals.records[0].state, 'expired');
  // Reconciliation from a current successor reports the closed lease; retrying
  // the old control returns evidence, never another native decision.
  await f.controller.handleControl(message('question.sync', { questions: [delivery.entry.question] }), () => {});
  assert.equal(last(f.wire).state, 'expired');
  await f.controller.handleControl(control, () => {}); assert.equal(f.calls(), 1);
});

test('peer revocation before dispatch refuses without consuming the pending native question', async t => {
  const f = fixture(t), delivery = await f.deliver();
  await assert.rejects(f.controller.handleControl(answer(delivery), () => { throw new Error('revoked control peer'); }), /revoked/);
  assert.equal(f.calls(), 0);
  assert.equal(f.wire.state.nativeApprovals.records[0].attempted, false);
  assert.equal(f.wire.state.nativeApprovals.controls.length, 0);
});

test('revocation after native application retains confirmed evidence without an answer receipt', async t => {
  let current = true;
  const assertPeer = () => { if (!current) throw new Error('revoked control peer'); };
  const f = fixture(t, { resolve(_params, request) { current = false; return outcome(request); } });
  const delivery = await f.deliver(), control = answer(delivery);
  await f.controller.handleControl(control, assertPeer);
  assert.equal(f.authorized(), true);
  assert.equal(f.wire.frames.some(frame => frame.state === 'answered' || frame.of === control.id), false);
  assert.equal(f.wire.state.nativeApprovals.records[0].state, 'resolved');
  assert.deepEqual(f.wire.state.nativeApprovals.controls[0].nativeOutcome, { applied: true, status: 'allowed', action: 'once' });
  await f.controller.handleControl(message('question.sync', { questions: [delivery.entry.question] }), () => {});
  assert.equal(last(f.wire).state, 'resolved'); assert.equal(last(f.wire).answer, undefined); assert.equal(last(f.wire).of, undefined);
  await f.controller.handleControl(control, () => {}); assert.equal(f.calls(), 1); assert.equal(last(f.wire).code, 'agent_unavailable');
});

test('ambiguous RPC failure expires the control lease and is never replayed', async t => {
  const f = fixture(t, { resolve() { throw new Error('lost response'); } }), delivery = await f.deliver();
  const control = answer(delivery); await f.controller.handleControl(control);
  assert.equal(last(f.wire).code, 'agent_unavailable');
  assert.equal(f.wire.frames.find(frame => frame.type === 'question.update').state, 'expired');
  await f.controller.handleControl(control); assert.equal(f.calls(), 1);
  await assert.rejects(f.controller.handleControl(answer(delivery)), { code: 'conflict' });
});

test('a lost RPC deadline never issues a late receipt or redispatches its decision', async t => {
  let complete;
  const f = fixture(t, { timeout: 5, resolve: (_params, request) => new Promise(resolve => { complete = () => resolve(outcome(request)); }) });
  const delivery = await f.deliver(), control = answer(delivery);
  // Keep the test process alive while the production deadline is unref'ed.
  const keepAlive = setTimeout(() => {}, 500); t.after(() => clearTimeout(keepAlive));
  await f.controller.handleControl(control);
  complete(); await Promise.resolve();
  assert.equal(last(f.wire).code, 'agent_unavailable');
  assert.equal(f.wire.frames.some(frame => frame.state === 'answered'), false);
  await f.controller.handleControl(control); assert.equal(f.calls(), 1);
});

test('canonical response must match request creation, complete command, decision and status', async t => {
  for (const mutate of [result => result.approval.createdAtMs++, result => result.approval.presentation.commandText += ' changed',
    result => result.approval.status = 'pending']) {
    const f = fixture(t, { resolve(_params, request) { const result = outcome(request); mutate(result); return result; } });
    const delivery = await f.deliver(); await f.controller.handleControl(answer(delivery));
    assert.equal(f.wire.frames.some(frame => frame.state === 'answered'), false);
  }
});

test('restart expires old cards, replay creates new bindings, and account revocation fences resolution', async t => {
  const first = fixture(t), delivery = await first.deliver(), snapshot = first.wire.snapshot;
  first.controller.close(); assert.equal(first.disposed(), true);
  const second = fixture(t, { saved: snapshot });
  assert.equal(last(second.wire).state, 'expired');
  const replayed = await second.deliver(delivery.request);
  assert.notEqual(replayed.entry.question, delivery.entry.question);
  await assert.rejects(second.controller.handleControl(answer(delivery)), { code: 'conflict' });
  second.revoke(); await assert.rejects(second.controller.handleControl(answer(replayed)), { code: 'unsupported' });
  assert.equal(second.calls(), 0);
});

test('reconciliation replays canonical terminal state and expires an unknown native card', async t => {
  const f = fixture(t), delivery = await f.deliver(); await f.settle(delivery, 'expired');
  const settlement = last(f.wire);
  await f.controller.handleControl(message('question.sync', { questions: [delivery.entry.question, 'ordinary', 'oc-exec-unknown'] }));
  assert.ok(f.wire.frames.includes(settlement)); assert.equal(last(f.wire).question, 'oc-exec-unknown'); assert.equal(last(f.wire).state, 'expired');
  f.wire.closed = true; f.controller.close();
});

test('retained-card capacity preserves evidence and sends complete native fallback without a binding', async t => {
  const f = fixture(t);
  let first;
  for (let i = 0; i < 128; i++) {
    const request = nativeRequest(); request.id = `capacity-${i}`;
    const delivery = await f.deliver(request); first ??= delivery;
    await f.settle(delivery, 'expired');
    // Model transport ACK, not deletion of the module's decision evidence.
    f.wire.state.outbox = [];
  }
  const request = nativeRequest(); request.id = 'beyond-capacity';
  const delivery = await f.deliver(request);
  assert.equal(delivery.entry.fallback, true);
  assert.match(f.wire.frames.filter(frame => frame.type === 'message.out').map(frame => frame.text).join('\n'), /registry is full/);
  await f.controller.handleControl(message('question.sync', { questions: [first.entry.question] }));
  assert.equal(last(f.wire).state, 'expired'); assert.equal(f.calls(), 0);
});

const installed = process.env.ENCLOS_OPENCLAW_PACKAGE;
test('installed public SDK delivers authoritative views and canonical resolver preserves exact reviewer', { skip: !installed }, async t => {
  const load = name => import(pathToFileURL(path.join(installed, `dist/plugin-sdk/${name}.js`)));
  const [delivery, handler, gateway, contexts] = await Promise.all(['approval-delivery-runtime', 'approval-handler-runtime',
    'approval-gateway-runtime', 'channel-runtime-context'].map(load));
  const request = nativeRequest();
  let context, calls = 0;
  const wire = transport();
  const factory = createNativeApprovals({ ...delivery, ...handler, ...contexts,
    resolveApprovalOverGateway(params) {
      return gateway.resolveApprovalOverGateway({ ...params, gatewayRuntime: { async request(method, payload) {
        calls++; assert.equal(method, 'approval.resolve');
        assert.deepEqual(payload, { id: request.id, kind: 'exec', decision: 'allow-once', reviewer: { channel: 'enclos', accountId: 'main', senderId: 'alice' } });
        assert.equal((await factory.approvalCapability.authorizeActorActionAsync({ cfg: {}, accountId: 'main', senderId: 'alice', action: 'approve', approvalKind: 'exec', request })).authorized, true);
        return outcome(request);
      } } });
    } });
  const controller = factory.attach(account, wire, { cfg: {}, sessionKeyFor, assertCurrent() {},
    channelRuntime: { runtimeContexts: { register(params) { context = params.context; assert.equal(params.capability, 'approval.native'); return { dispose() {} }; } } } });
  t.after(() => controller.close());
  const runtime = await handler.createChannelApprovalHandlerFromCapability({ capability: factory.approvalCapability,
    label: 'enclos-test', clientDisplayName: 'enclos test', channel: 'enclos', channelLabel: 'enclos', cfg: {}, accountId: 'main', context });
  // Direct lifecycle calls exercise public SDK views/routes without starting a
  // gateway client, subscribing to host state or executing any command.
  await runtime.handleRequested(request);
  const ask = wire.frames.find(frame => frame.type === 'question.ask');
  assert.ok(ask); assert.equal(ask.question.approval.command, request.request.command);
  assert.deepEqual(ask.question.approval.actions, ['once', 'always', 'deny']);
  const control = message('question.answer', { question: ask.question.id, conversation: 'one', answer: { kind: 'approval', action: 'once' } });
  await controller.handleControl(control);
  assert.equal(calls, 1); assert.equal(last(wire).state, 'answered'); assert.equal(last(wire).of, control.id);
  await runtime.handleResolved({ id: request.id, decision: 'allow-once', ts: Date.now(), request: request.request });
  const oneShot = nativeRequest({ ask: 'always' }); oneShot.id = 'native-one-shot';
  await runtime.handleRequested(oneShot);
  assert.deepEqual(last(wire).question.approval.actions, ['once', 'deny']);
  const before = wire.frames.length;
  const remote = nativeRequest({ host: 'node', nodeId: 'remote' }); remote.id = 'remote-request';
  await runtime.handleRequested(remote); assert.equal(wire.frames.length, before);
  await runtime.stop();
});
