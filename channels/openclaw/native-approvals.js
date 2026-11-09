// Native exec approvals through OpenClaw's public channel approval capability.
// No Gateway admin client, general method dispatch or native storage access.
import { createHash, randomUUID } from 'node:crypto';
import { checkedId, message, ProtocolError } from './protocol.js';

const PREFIX = 'oc-exec-';
const MAX_RECORDS = 128;
const MAX_CONTROLS = 256;
const MAX_DEFINITION = 24 * 1024;
const MAX_SCOPES = 8 * 1024;
const actions = new Map([['allow-once', 'once'], ['allow-always', 'always'], ['deny', 'deny']]);
const decisions = new Map([...actions].map(([native, wire]) => [wire, native]));
const ordered = ['once', 'always', 'deny'];
const bytes = value => Buffer.byteLength(JSON.stringify(value));
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const supports = hello => ['runtime_approvals', 'runtime_approval_scopes'].every(c => hello?.capabilities?.includes(c));
const terminal = state => ['answered', 'resolved', 'expired', 'cancelled'].includes(state);
const settledState = status => ['expired', 'cancelled'].includes(status) ? status : 'resolved';

function text(value, name) {
  if (typeof value !== 'string' || !value.trim() || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/u.test(value)) throw new Error(`invalid native approval ${name}`);
  return value;
}

function literal(value, language = 'text') {
  const candidates = ['`', '~'].map(c => [c, Math.max(3, ...value.split(new RegExp(`[^${c}]`, 'u')).map(s => s.length + 1))]);
  const [c, n] = candidates.sort((a, b) => a[1] - b[1])[0];
  const fence = c.repeat(n);
  return `${fence}${language}\n${value}\n${fence}`;
}

function split(value) {
  const chunks = []; let chunk = '', size = 0;
  for (const c of value) {
    const next = Buffer.byteLength(c);
    if (size + next > 8000) { chunks.push(chunk); chunk = ''; size = 0; }
    chunk += c; size += next;
  }
  if (chunk) chunks.push(chunk);
  return chunks;
}

function validateDefinition(definition) {
  checkedId(definition?.id, 'question'); text(definition?.text, 'heading');
  if (definition.multiple !== false || !Array.isArray(definition.choices) || definition.choices.length || definition.approval?.smart_denied !== false) throw new Error('invalid native approval shape');
  const approval = definition.approval;
  text(approval?.command, 'display command'); text(approval?.reason, 'reason');
  const offered = approval?.actions;
  if (!Array.isArray(offered) || !offered.includes('deny') || offered.some(a => !ordered.includes(a)) ||
      JSON.stringify(offered) !== JSON.stringify(ordered.filter(a => offered.includes(a))) ||
      (offered.length > 1 && !offered.includes('once'))) throw new Error('invalid native approval actions');
  text(approval.scopes?.description, 'scope description'); text(approval.scopes?.fallback, 'instructions');
  if (bytes(approval.scopes) > MAX_SCOPES || bytes(definition) > MAX_DEFINITION) throw new Error('native approval exceeds structured bounds');
}

function fingerprint(request) {
  const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
  return digest(stable([request?.id, request?.createdAtMs, request?.expiresAtMs, request?.request]));
}

function display(request, view, id) {
  if (view?.approvalKind !== 'exec' || view?.phase !== 'pending' || view?.approvalId !== request.id || view.expiresAtMs !== request.expiresAtMs) throw new Error('native approval view does not match its exec request');
  const nativeActions = view.actions;
  if (!Array.isArray(nativeActions) || !nativeActions.length || nativeActions.some(a => !actions.has(a.decision))) throw new Error('unsupported native approval action');
  const offered = nativeActions.map(a => actions.get(a.decision));
  const command = text(view.commandText, 'complete display command');
  const details = [view.description, view.warningText,
    ...(view.metadata ?? []).map(item => `${text(item.label, 'metadata label')}: ${text(item.value, 'metadata value')}`),
    ...(view.cwd ? [`Working directory: ${text(view.cwd, 'working directory')}`] : []),
    ...(view.scope ? [`Native scope: ${JSON.stringify(view.scope)}`] : []),
    `Native request expires: ${new Date(request.expiresAtMs).toISOString()}`,
  ].filter(value => value != null && value !== '').map(value => text(value, 'reason'));
  const fallback = nativeActions.every(a => typeof a.command === 'string' && a.command.trim())
    ? `Use OpenClaw's native approval surface for request ${request.id}. Native instructions (these are not unbound shortcuts through enclos):\n` + nativeActions.map(a => `${text(a.label, 'action label')}: ${text(a.command, 'native answer command')}`).join('\n')
    : `Use OpenClaw's native approval surface for request ${request.id}. Offered actions: ${offered.join(', ')}.`;
  const description = offered.includes('always')
    ? 'Allow once permits this pending OpenClaw operation. Always allow persists an OpenClaw command allowlist grant, whose executable and argument matching policy is owned by OpenClaw. Deny refuses this request.'
    : 'Allow once, when offered, permits only this pending OpenClaw operation. Deny refuses this request. No persistent grant is offered.';
  return { id, text: text(view.title || 'OpenClaw command approval', 'heading'), choices: [], multiple: false,
    approval: { command, reason: details.join('\n') || 'OpenClaw requires consent before this operation continues.',
      actions: offered, smart_denied: false, scopes: { description, fallback } } };
}

/** Register this capability on the channel and attach one controller per account. */
export function createNativeApprovals(sdk, { now = Date.now, requestTimeoutMs = 20000 } = {}) {
  for (const name of ['createChannelApprovalCapability', 'createChannelApprovalNativeRuntimeAdapterAsync', 'resolveApprovalOverGateway', 'registerChannelRuntimeContext']) {
    if (typeof sdk?.[name] !== 'function') throw new Error(`OpenClaw's public ${name} approval contract is unavailable`);
  }
  if (sdk.CHANNEL_APPROVAL_NATIVE_RUNTIME_CONTEXT_CAPABILITY !== 'approval.native') throw new Error('unsupported native approval context contract');
  const controllers = new Map();
  const at = params => controllers.get(params.accountId);
  const current = params => { const owner = at(params); return owner?.isCurrent() ? owner : null; };
  const owned = params => {
    const owner = current(params);
    if (!owner || params.context !== owner) throw new Error('native approval context is no longer current');
    return owner;
  };
  const nativeRuntimeAsync = sdk.createChannelApprovalNativeRuntimeAdapterAsync({
    eventKinds: ['exec'],
    availability: {
      isConfigured: params => Boolean(current(params)),
      shouldHandle: params => Boolean(current(params)?.target(params.request, params.approvalKind)),
    },
    presentation: {
      buildPendingPayload: params => owned(params).prepare(params.request, params.view),
      buildResolvedResult(params) { owned(params).settle(params.entry, params.request, 'resolved'); return { kind: 'leave' }; },
      buildExpiredResult(params) { owned(params).settle(params.entry, params.request, 'expired'); return { kind: 'leave' }; },
    },
    transport: {
      prepareTarget(params) {
        const owner = owned(params), route = owner.target(params.request, params.approvalKind);
        return route && params.plannedTarget?.target?.to === route.conversation && params.plannedTarget.target.threadId == null
          ? { dedupeKey: digest([owner.account.accountId, params.request.id]), target: route } : null;
      },
      deliverPending(params) { return owned(params).deliver(params.pendingPayload, params.request, params.preparedTarget); },
    },
  });
  const approvalCapability = sdk.createChannelApprovalCapability({
    nativeRuntimeAsync,
    authorizeActorActionAsync: async params => ({ authorized: Boolean(current(params)?.authorize(params)) }),
    getActionAvailabilityStateAsync: async params => ({ kind: params.approvalKind != null && params.approvalKind !== 'exec' ? 'unsupported' : current(params) ? 'enabled' : 'disabled' }),
    getExecInitiatingSurfaceStateAsync: async params => ({ kind: current(params) ? 'enabled' : 'disabled' }),
    native: {
      describeDeliveryCapabilities: params => ({ enabled: Boolean(current(params)?.target(params.request, params.approvalKind)),
        preferredSurface: 'origin', supportsOriginSurface: true, supportsApproverDmSurface: false }),
      resolveOriginTarget: params => { const route = current(params)?.target(params.request, params.approvalKind); return route ? { to: route.conversation } : null; },
    },
    describeExecApprovalSetup: () => 'Use OpenClaw\'s native approval surface when this channel cannot prove the exact local request and conversation. Structured remote-node approvals are unavailable.',
  });

  function attach(account, transport, context) {
    if (controllers.has(account.accountId)) throw new Error('native approvals already attached to this account');
    if (typeof context?.assertCurrent !== 'function' || typeof context?.sessionKeyFor !== 'function') throw new Error('native approvals require current account and session attribution');
    const generation = randomUUID(), live = new Map(), attempts = new Map();
    const saved = transport.state.nativeApprovals ?? { v: 1, records: [], controls: [] };
    if (saved.v !== 1 || !Array.isArray(saved.records) || saved.records.length > MAX_RECORDS || !Array.isArray(saved.controls) || saved.controls.length > MAX_CONTROLS) throw new Error('invalid native approval state');
    const records = new Map(), controls = new Map();
    for (const record of saved.records) {
      checkedId(record?.id, 'question');
      if (!record.id.startsWith(PREFIX) || record.definition?.id !== record.id || (!terminal(record.state) && record.state !== 'pending')) throw new Error('invalid saved native approval');
      validateDefinition(record.definition); checkedId(record.conversation, 'conversation');
      checkedId(record.person, 'person');
      if (records.has(record.id)) throw new Error('duplicate saved native approval');
      if (record.ask && (record.ask.type !== 'question.ask' || record.ask.question?.id !== record.id || record.ask.conversation !== record.conversation || digest(record.ask.question) !== digest(record.definition))) throw new Error('invalid saved native approval delivery');
      if (terminal(record.state) && (!record.last || record.last.type !== 'question.update' || record.last.question !== record.id || record.last.state !== record.state)) throw new Error('invalid saved native approval settlement');
      records.set(record.id, record);
    }
    for (const control of saved.controls) {
      checkedId(control?.id); checkedId(control.question, 'question');
      if (!/^[0-9a-f]{64}$/u.test(control.hash ?? '')) throw new Error('invalid saved native approval receipt');
      const outcome = control.nativeOutcome;
      if (outcome != null && (typeof outcome.applied !== 'boolean' || !['allowed', 'denied', 'expired', 'cancelled'].includes(outcome.status) ||
          (outcome.applied ? !decisions.has(outcome.action) || outcome.status !== (outcome.action === 'deny' ? 'denied' : 'allowed') : outcome.action != null))) throw new Error('invalid saved native approval outcome');
      if (controls.has(control.id)) throw new Error('duplicate saved native approval receipt');
      controls.set(control.id, control);
    }
    let closed = false, registration;
    const persist = () => {
      const before = transport.state.nativeApprovals;
      transport.state.nativeApprovals = { v: 1, records: [...records.values()], controls: [...controls.values()] };
      try { transport.save(); } catch (error) { transport.state.nativeApprovals = before; throw error; }
    };
    const retain = envelope => {
      if (transport.closed) return;
      if (transport.state.outbox.some(existing => existing.id === envelope.id)) transport.write(envelope);
      else transport.enqueue(envelope);
    };
    const update = (record, state, { action, of } = {}) => {
      if (terminal(record.state)) return record.last;
      record.state = state;
      record.last = message('question.update', { question: record.id, state,
        ...(action ? { answer: { kind: 'approval', action } } : {}), ...(of ? { of } : {}) });
      persist(); retain(record.last);
      if (!transport.closed && record.fallbackSent && !supports(transport.bridgeHello)) transport.send(record.conversation,
        `OpenClaw approval ${state}. Consent is separate from execution.`, { kind: 'status' });
      return record.last;
    };
    const fallback = (record, limitation) => {
      if (record.fallbackSent) return;
      const a = record.definition.approval;
      for (const part of split(a.command)) transport.send(record.conversation, `OpenClaw approval (native fallback)\n\n${literal(part, 'sh')}`, { kind: 'reply' });
      for (const part of split(`${limitation ?? 'Structured native approval scopes are unavailable on this bridge. Use OpenClaw\'s native approval surface.'}\n\n${record.definition.text}\n\nWhy: ${a.reason}\n\n${a.scopes.description}\n\n${a.actions.join(' / ')}\n${a.scopes.fallback}`)) transport.send(record.conversation, literal(part), { kind: 'reply' });
      record.fallbackSent = true; persist();
    };
    const owner = {
      account,
      isCurrent() { if (closed || !registration || transport.closed || context.abortSignal?.aborted) return false; try { context.assertCurrent(); return true; } catch { return false; } },
      target(request, kind = 'exec') {
        if (!owner.isCurrent() || kind !== 'exec' || (request?.approvalKind != null && request.approvalKind !== 'exec')) return null;
        const p = request?.request;
        if (p?.agentId !== account.agentId || p.turnSourceChannel !== 'enclos' || p.turnSourceAccountId !== account.accountId ||
            !['gateway', 'sandbox'].includes(p.host) || p.nodeId || p.turnSourceThreadId != null ||
            typeof request.id !== 'string' || !Number.isSafeInteger(request.createdAtMs) || request.createdAtMs < 0 ||
            !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.createdAtMs || request.expiresAtMs <= now()) return null;
        const conversation = p.turnSourceTo;
        try { checkedId(conversation, 'conversation'); checkedId(request.id, 'native approval'); } catch { return null; }
        const route = transport.state.routes[conversation];
        if (!route?.person || p.sessionKey !== context.sessionKeyFor(conversation, route.person)) return null;
        try { checkedId(conversation, 'conversation'); checkedId(route.person, 'person'); checkedId(request.id, 'native approval'); } catch { return null; }
        return { conversation, person: route.person, sessionKey: p.sessionKey };
      },
      authorize(params) {
        if (params.approvalKind !== 'exec' || !params.request || !owner.target(params.request)) return false;
        const attempt = attempts.get(params.request.id);
        if (!attempt) return false;
        try { attempt.assertControlCurrent(); } catch { return false; }
        return Boolean(attempt.record.state === 'pending' && params.senderId === attempt.record.person &&
          fingerprint(params.request) === fingerprint(attempt.native));
      },
      prepare(request, view) {
        const route = owner.target(request);
        if (!route) throw new Error('native approval has no exact local conversation route');
        const id = PREFIX + digest([account.accountId, account.agentId, generation, request.id, request.createdAtMs]);
        const definition = display(request, view, id);
        return { route, definition, native: request };
      },
      deliver(payload, request, preparedTarget) {
        const route = owner.target(request);
        if (!route || fingerprint(payload.native) !== fingerprint(request) || route.conversation !== preparedTarget.conversation || route.person !== preparedTarget.person) throw new Error('native approval target changed');
        const id = payload.definition.id;
        if (records.has(id)) return { question: id, native: request.id };
        const record = { id, conversation: route.conversation, person: route.person,
          definition: payload.definition, state: 'pending', attempted: false };
        if (records.size >= MAX_RECORDS) {
          fallback(record, 'The enclos native approval registry is full (128 retained cards). No app answer was bound. Use OpenClaw\'s native approval surface.');
          return { fallback: true, native: request.id };
        }
        // Oversized native displays retain complete text fallback but never
        // acquire a lossy structured card or an answer binding.
        try { validateDefinition(record.definition); }
        catch { fallback(record, 'The native approval exceeds the app\'s structured display contract. No lossy card or app answer was bound. Use OpenClaw\'s native approval surface.'); return { fallback: true, native: request.id }; }
        records.set(id, record); persist();
        try {
          if (supports(transport.bridgeHello)) {
            record.ask = message('question.ask', { conversation: record.conversation, question: record.definition });
            persist(); retain(record.ask);
          } else fallback(record);
        } catch (error) { records.delete(id); persist(); throw error; }
        live.set(id, { record, native: request, inFlight: null, deferred: null });
        return { question: id, native: request.id };
      },
      settle(entry, request, state) {
        if (!entry?.question || entry.native !== request.id) return;
        const binding = live.get(entry.question);
        if (!binding || fingerprint(binding.native) !== fingerprint(request)) return;
        if (binding.inFlight) { binding.deferred = state; return; }
        update(binding.record, state); live.delete(entry.question);
      },
      capabilities(hello) { return owner.isCurrent() && supports(hello) ? ['runtime_approvals', 'runtime_approval_scopes'] : []; },
      canDeliver(envelope, hello) {
        const id = envelope.type === 'question.ask' ? envelope.question?.id : envelope.question;
        return !['question.ask', 'question.update'].includes(envelope.type) || typeof id !== 'string' || !id.startsWith(PREFIX) || supports(hello);
      },
      onHello(hello) {
        if (!owner.isCurrent()) return;
        for (const record of records.values()) {
          if (terminal(record.state)) { if (record.last) retain(record.last); continue; }
          if (!live.has(record.id)) continue;
          if (supports(hello)) {
            record.ask ??= message('question.ask', { conversation: record.conversation, question: record.definition });
            persist(); retain(record.ask);
          } else fallback(record);
        }
      },
      async handleControl(control, assertControlCurrent = () => {}) {
        if (control.type === 'question.sync') {
          assertControlCurrent();
          if (!Array.isArray(control.questions) || control.questions.length > 128) throw new ProtocolError('bad_message', 'invalid question reconciliation batch', control.id);
          const ids = control.questions.filter(id => typeof id === 'string' && id.startsWith(PREFIX));
          for (const id of ids) {
            checkedId(id, 'question');
            const record = records.get(id);
            if (!record) retain(message('question.update', { question: id, state: 'expired' }));
            else if (terminal(record.state) && record.last) retain(record.last);
            else if (record.ask && live.has(id)) retain(record.ask);
          }
          return ids.length > 0;
        }
        if (control.type !== 'question.answer' || typeof control.question !== 'string' || !control.question.startsWith(PREFIX)) return false;
        assertControlCurrent();
        checkedId(control.id); checkedId(control.question, 'question'); checkedId(control.conversation, 'conversation');
        const hash = digest([control.question, control.conversation, control.answer]);
        const old = controls.get(control.id);
        if (old) {
          if (old.hash !== hash) throw new ProtocolError('conflict', 'approval control id was reused', control.id);
          if (old.response) { if (old.response.type === 'error') transport.write(old.response); else retain(old.response); return true; }
          throw new ProtocolError('agent_unavailable', 'this native decision is uncertain and will not be retried', control.id);
        }
        const binding = live.get(control.question), record = binding?.record;
        if (!owner.isCurrent() || !supports(transport.bridgeHello)) throw new ProtocolError('unsupported', 'native approval scopes are not negotiated', control.id);
        if (!binding || record.state !== 'pending' || record.conversation !== control.conversation || !owner.target(binding.native)) throw new ProtocolError('conflict', 'this exact native approval is no longer pending', control.id);
        const answer = control.answer, action = answer?.action;
        if (answer?.kind !== 'approval' || Object.keys(answer).sort().join(',') !== 'action,kind' || !record.definition.approval.actions.includes(action)) throw new ProtocolError('bad_message', 'choose an offered native approval action', control.id);
        if (record.attempted) throw new ProtocolError('agent_unavailable', 'a prior native decision is uncertain; use the native surface', control.id);
        if (controls.size >= MAX_CONTROLS) {
          fallback(record, 'The enclos native decision receipt registry is full (256 retained receipts). No decision was sent. Use OpenClaw\'s native approval surface.');
          update(record, 'expired'); live.delete(record.id);
          throw new ProtocolError('agent_unavailable', 'native control receipt registry is full; no decision was sent', control.id);
        }
        const receipt = { id: control.id, question: record.id, hash };
        controls.set(control.id, receipt); record.attempted = true; persist();
        binding.inFlight = control.id; binding.assertControlCurrent = assertControlCurrent; attempts.set(binding.native.id, binding);
        let timer;
        try {
          assertControlCurrent();
          const outcome = await Promise.race([
            sdk.resolveApprovalOverGateway({ cfg: context.cfg, approvalKind: 'exec', approvalId: binding.native.id,
              decision: decisions.get(action), channel: 'enclos', accountId: account.accountId, senderId: record.person }),
            new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('native approval deadline')), requestTimeoutMs); timer.unref?.(); }),
          ]);
          const canonical = outcome?.approval;
          if (typeof outcome?.applied !== 'boolean' || canonical?.id !== binding.native.id || canonical?.presentation?.kind !== 'exec' ||
              canonical.createdAtMs !== binding.native.createdAtMs || canonical.expiresAtMs !== binding.native.expiresAtMs ||
              canonical.presentation.commandText !== record.definition.approval.command) throw new Error('native approval result does not identify this request');
          if (!['allowed', 'denied', 'expired', 'cancelled'].includes(canonical.status) ||
              (outcome.applied && (canonical.decision !== decisions.get(action) || canonical.status !== (action === 'deny' ? 'denied' : 'allowed')))) throw new Error('native approval decision was not confirmed');
          // A confirmed native decision remains evidence even when its source
          // peer is revoked before receipt publication. It never authorizes a
          // retry or turns a successor connection into the consenting peer.
          receipt.nativeOutcome = { applied: outcome.applied, status: canonical.status, ...(outcome.applied ? { action } : {}) };
          persist();
          assertControlCurrent();
          if (!owner.isCurrent()) throw new Error('native channel stopped while the decision was in flight');
          if (outcome.applied && canonical.decision === decisions.get(action) && canonical.status === (action === 'deny' ? 'denied' : 'allowed')) {
            receipt.response = update(record, 'answered', { action, of: control.id });
          } else {
            update(record, settledState(canonical.status));
            receipt.response = message('error', { of: control.id, code: 'conflict', message: 'The native approval was settled elsewhere; no decision receipt was issued.' });
            transport.write(receipt.response);
          }
          persist(); live.delete(record.id);
        } catch {
          if (record.state === 'pending') { update(record, receipt.nativeOutcome ? settledState(receipt.nativeOutcome.status) : binding.deferred ?? 'expired'); live.delete(record.id); }
          receipt.response = message('error', { of: control.id, code: 'agent_unavailable', message: receipt.nativeOutcome
            ? 'OpenClaw settled this request, but its originating bridge lost receipt authority. Refresh the canonical state; this decision will not be retried.'
            : 'The native decision was not confirmed. Its outcome may be unknown; it will not be retried.' });
          persist();
          try { assertControlCurrent(); transport.write(receipt.response); } catch { /* Only canonical terminal state may reach a successor peer. */ }
        } finally { clearTimeout(timer); attempts.delete(binding.native.id); binding.inFlight = null; binding.assertControlCurrent = undefined; }
        return true;
      },
      close() {
        if (closed) return;
        closed = true; registration?.dispose(); controllers.delete(account.accountId);
        // Shutdown must still release the account when a full outbox or a
        // disk error prevents a final display update. Restart invalidates all
        // old bindings before any new controls can be accepted.
        for (const binding of live.values()) { try { update(binding.record, 'cancelled'); } catch { /* No native decision is made. */ } }
        live.clear();
      },
    };
    // Old process-local bindings never survive a restart. A real native
    // replay can create a new card, with a new generation and exact id.
    for (const record of records.values()) if (record.state === 'pending') update(record, 'expired');
    controllers.set(account.accountId, owner);
    registration = sdk.registerChannelRuntimeContext({ channelRuntime: context.channelRuntime, channelId: 'enclos',
      accountId: account.accountId, capability: sdk.CHANNEL_APPROVAL_NATIVE_RUNTIME_CONTEXT_CAPABILITY,
      context: owner, abortSignal: context.abortSignal });
    if (!registration) { controllers.delete(account.accountId); closed = true; throw new Error('OpenClaw did not provide the native approval context registry'); }
    return Object.fromEntries(['capabilities', 'canDeliver', 'onHello', 'handleControl', 'close'].map(key => [key, owner[key]]));
  }
  return { approvalCapability, attach };
}
