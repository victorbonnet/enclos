// OpenClaw public channel contract. Native imports live in index.js.
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import path from 'node:path';
import { ChannelTransport, readToken } from './transport.js';
import { checkedId, message, ProtocolError } from './protocol.js';
import { commandCatalog, registerFeatures } from './features.js';
import { RoutineInventory } from './routines.js';
import { ModelSettings } from './model.js';
import { inboundMedia, mediaFolder, withStagedMedia } from './media.js';
import { createNativeTitles } from './native-titles.js';
import { createNativeTurns } from './native-turns.js';
import { createActivity } from './activity.js';
import { registerUsage } from './usage.js';
import { hostSender } from './host-messages.js';

export const TESTED_OPENCLAW = '2026.11.5';
const MINIMUM_OPENCLAW = '2026.11.5';
const release = /^v?(\d+\.\d+\.\d+)([+-].+)?$/u;
function supportsRelease(version) {
  const parts = typeof version === 'string' && release.exec(version);
  if (!parts) return false;
  const order = parts[1].localeCompare(MINIMUM_OPENCLAW, 'en', { numeric: true });
  return order > 0 || (order === 0 && !parts[2]?.startsWith('-'));
}
const nativeId = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

export function resolveAccount(cfg, accountId) {
  const section = cfg.channels?.enclos;
  const accounts = section?.accounts ?? {};
  const ids = Object.keys(accounts);
  if (ids.length > 512) throw new Error('enclos supports at most 512 configured channel accounts');
  const id = accountId ?? section?.defaultAccount ?? (ids.length === 1 ? ids[0] : undefined);
  if (!id || !nativeId.test(id) || !Object.hasOwn(accounts, id)) throw new Error('enclos needs an explicit configured account id');
  const value = accounts[id];
  if (!value || typeof value !== 'object' || !nativeId.test(value.agentId ?? '')) throw new Error('enclos account needs its native agentId');
  for (const key of ['socket', 'tokenFile']) if (typeof value[key] !== 'string' || !path.isAbsolute(value[key])) throw new Error(`enclos account ${key} must be an absolute path`);
  if (value.stateDir != null && (typeof value.stateDir !== 'string' || !path.isAbsolute(value.stateDir))) throw new Error('enclos stateDir must be an absolute path');
  checkedId(value.home, 'home');
  return {
    accountId: id, agentId: value.agentId, socket: value.socket,
    tokenFile: value.tokenFile, home: value.home, bridgeKey: value.bridgeKey,
    stateDir: value.stateDir ?? path.join(path.dirname(value.socket), 'openclaw-state', id),
    enabled: section?.enabled !== false && value.enabled !== false,
  };
}

export function sessionPeer(conversation, person) {
  checkedId(conversation, 'conversation'); checkedId(person, 'person');
  return createHash('sha256').update(JSON.stringify([conversation, person])).digest('hex');
}

function accountKey(account) { return JSON.stringify([account.accountId, account.agentId, account.socket, account.tokenFile, account.stateDir, account.bridgeKey]); }
function target(raw, account) {
  const value = typeof raw === 'string' && raw.startsWith('enclos:') ? raw.slice(7) : raw;
  return checkedId(!value || value === 'home' ? account.home : value, 'conversation');
}

export function createChannel(sdk = {}) {
  let runtime;
  const running = new Map();
  const outboundCaller = new AsyncLocalStorage();
  const sessionRoutes = new Map();
  const routines = new RoutineInventory();
  const models = new ModelSettings({ catalogue: sdk.models, runtime: () => runtime });
  let hooks = { tools: false, policy: false }, usage = false;
  const hasMedia = typeof sdk.loadMedia === 'function' && typeof sdk.mediaRoots === 'function';
  const currentConfig = fallback => runtime?.config?.current?.() ?? fallback;
  const assertCurrent = (cfg, account, transport) => {
    const now = resolveAccount(currentConfig(cfg), account.accountId), active = running.get(account.accountId);
    if (!now.enabled || accountKey(now) !== accountKey(account) || transport.closed || active?.transport !== transport ||
        accountKey(active.account) !== accountKey(account)) {
      throw new Error('enclos channel account was stopped or reconfigured');
    }
  };

  function setRuntime(value) {
    // version is part of the installed public PluginRuntimeCore contract.
    if (!supportsRelease(value?.version)) throw new Error(`Update OpenClaw to ${MINIMUM_OPENCLAW} or newer before enabling the enclos channel.`);
    runtime = value;
  }

  function findTurn(ctx) {
    if (!ctx?.sessionKey) return undefined;
    const turn = sessionRoutes.get(ctx.sessionKey);
    if (!turn || (ctx.agentId && ctx.agentId !== turn.active.account.agentId) ||
        (ctx.accountId && ctx.accountId !== turn.active.account.accountId) ||
        (ctx.messageChannel && ctx.messageChannel !== 'enclos')) return undefined;
    return turn;
  }
  const assertTurn = turn => assertCurrent(turn.active.cfg, turn.active.account, turn.active.transport);
  // A call's app conversation: its turn's, else, for a native chat this
  // process has not dispatched a message to yet (a routine delivering into
  // it, or since a restart), the saved route whose native session key it is,
  // or Home's, worked out without saving a route: observing a call changes
  // nothing. Not kept in `sessionRoutes`, which also opens tools and policy
  // context.
  function appTurn(ctx) {
    const turn = findTurn(ctx);
    if (turn || !ctx?.sessionKey || [ctx.messageChannel, ctx.messageProvider, ctx.channel].some(c => c && c !== 'enclos')) return turn;
    for (const active of running.values()) {
      if ((ctx.agentId && ctx.agentId !== active.account.agentId) || (ctx.accountId && ctx.accountId !== active.account.accountId)) continue;
      const { transport } = active;
      for (const conversation of new Set([...Object.keys(transport.state.routes), transport.home])) {
        let key;
        try { key = active.peekSessionKey(conversation); } catch { continue; }
        if (key === ctx.sessionKey) return { active, conversation };
      }
    }
    return undefined;
  }
  const appSession = ctx => [ctx?.messageChannel, ctx?.messageProvider, ctx?.channel].includes('enclos');
  function registerFull(api) {
    hooks = registerFeatures(api, { findTurn, assertTurn, running });
    usage = registerUsage(api, { appTurn, appSession, assertTurn, running });
    routines.register(api);
  }

  async function startAccount(ctx) {
    if (!runtime) throw new Error('Load the OpenClaw plugin runtime before starting the enclos channel.');
    const channel = ctx.channelRuntime ?? runtime.channel;
    const required = {
      'inbound.ingress.resolve': channel?.inbound?.ingress?.resolve,
      'inbound.buildContext': channel?.inbound?.buildContext,
      'inbound.dispatch': channel?.inbound?.dispatch,
      'routing.resolveAgentRoute': channel?.routing?.resolveAgentRoute,
      'routing.buildAgentSessionKey': channel?.routing?.buildAgentSessionKey,
    };
    const missing = Object.keys(required).filter(name => typeof required[name] !== 'function');
    if (missing.length) throw new Error(`OpenClaw is missing channel interfaces: ${missing.join(', ')}. Update the enclos channel or OpenClaw.`);
    const account = resolveAccount(ctx.cfg, ctx.accountId);
    if (!account.enabled) throw new Error('enclos account is disabled');
    if (running.has(account.accountId)) throw new Error('enclos account is already running');
    if (hasMedia) mediaFolder(account);
    let transport, titles, approvals, activity;
    const turns = createNativeTurns(() => assertCurrent(ctx.cfg, account, transport));
    const controllers = () => [turns, titles, approvals, activity].filter(Boolean);
    const keyForPeer = peer => channel.routing.buildAgentSessionKey({ agentId: account.agentId, channel: 'enclos', accountId: account.accountId,
      peer: { kind: 'direct', id: peer }, dmScope: 'per-account-channel-peer' });
    const sessionKeyFor = (conversation, person) => {
      const saved = transport.state.routes[conversation] ?? (conversation === transport.home ? transport.homeRoute() : undefined);
      if (!saved) return undefined;
      if (person != null && saved.person !== person) throw new ProtocolError('not_allowed', 'native conversation belongs to another person');
      return keyForPeer(saved.peer);
    };
    // The native session key a conversation has, or Home would have, saving
    // nothing: for usage, which only observes a call.
    const peekSessionKey = conversation => {
      const peer = transport.state.routes[conversation]?.peer ??
        (conversation != null && conversation === transport.home ? transport.homePeer(conversation) : undefined);
      return peer === undefined ? undefined : keyForPeer(peer);
    };
    transport = new ChannelTransport(account, {
      supportsAttachments: hasMedia,
      capabilities: hello => ['typing', 'abort', ...(hasMedia ? ['attachments'] : []), ...(sdk.commands ? ['commands'] : []), ...(hooks.tools ? ['tools'] : []), ...(hooks.policy ? ['approval'] : []), ...(titles?.available ? ['titles'] : []), ...(routines.available() ? ['routines'] : []), ...(models.available() ? ['model'] : []), ...(usage ? ['usage', 'agent_usage'] : []), ...controllers().flatMap(controller => controller.capabilities?.(hello) ?? [])],
      canDeliver: (frame, hello) => controllers().every(controller => controller.canDeliver?.(frame, hello) !== false),
      onHello(hello, owner) {
        if (sdk.commands) owner.write(message('commands', { commands: commandCatalog(sdk.commands, currentConfig(ctx.cfg)) }));
        for (const controller of controllers()) controller.onHello?.(hello);
      },
      async onControl(control, owner, requestPeer) {
        owner.assertControlPeer(requestPeer);
        if (control.type === 'model.request') {
          return models.handle(control, { account,
            assertCurrent: () => {
              assertCurrent(currentConfig(ctx.cfg), account, owner);
              owner.assertControlPeer(requestPeer);
            },
            write: response => owner.write(response, requestPeer) });
        }
        if (control.type === 'routine.request') {
          return routines.handle(control, { account,
            assertCurrent: () => {
              assertCurrent(currentConfig(ctx.cfg), account, owner);
              owner.assertControlPeer(requestPeer);
            },
            write: response => owner.write(response, requestPeer) });
        }
        // Reconciliation batches may mix module-owned question ids. Every
        // controller must see them even when an earlier one handled a part.
        let handled = false;
        for (const controller of controllers()) {
          const accepted = await controller.handleControl?.(control, () => owner.assertControlPeer(requestPeer));
          handled = accepted === true || handled;
        }
        if (handled) return;
        owner.assertControlPeer(requestPeer);
        if (control.type !== 'policy.context' || !hooks.policy) throw new ProtocolError('unsupported', 'this native control is unavailable');
        if (typeof control.text !== 'string' || Buffer.byteLength(control.text) > 48 * 1024) throw new ProtocolError('bad_message', 'policy context must be at most 48 KiB of text');
        const before = owner.state.policyContext;
        owner.state.policyContext = control.text;
        try { owner.save(); } catch (error) { owner.state.policyContext = before; throw error; }
      },
      async onMessage(incoming, route) {
        const execution = turns.begin(incoming);
        try {
        const cfg = currentConfig(ctx.cfg);
        const assertAuthority = () => { assertCurrent(cfg, account, transport); execution.signal.throwIfAborted(); };
        assertAuthority();
        // Checked first, on receipt: the bridge signed it as it sent it.
        const sandbox = process.env.ENCLOS_SANDBOX;
        const sender = hostSender(account.bridgeKey, sandbox && `${sandbox}/${account.agentId}`, incoming);
        if (sender.failure) (ctx.log?.warn ?? console.warn)(`enclos: a signed message is passed on as its person's, not the owner's: ${sender.failure}`);
        if (sender.refused) throw new ProtocolError('not_allowed', sender.refused);
        const media = hasMedia ? inboundMedia(account, incoming.attachments, incoming.id) : [];
        const nativeRoute = channel.routing.resolveAgentRoute({ cfg, channel: 'enclos', accountId: account.accountId,
          peer: { kind: 'direct', id: incoming.conversation }, dmScope: 'per-account-channel-peer' });
        if (nativeRoute.agentId !== account.agentId || nativeRoute.matchedBy === 'default') throw new Error('enclos account needs an explicit native binding to its agent');
        const sessionKey = channel.routing.buildAgentSessionKey({ agentId: account.agentId, channel: 'enclos',
          accountId: account.accountId, peer: { kind: 'direct', id: route.peer }, dmScope: 'per-account-channel-peer' });
        titles?.watch(incoming.conversation);
        sessionRoutes.set(sessionKey, { active: running.get(account.accountId), conversation: incoming.conversation });
        const isCommand = channel.text?.hasControlCommand?.(incoming.text, cfg) ?? incoming.text.trimStart().startsWith('/');
        const ingress = await channel.inbound.ingress.resolve({
          channelId: 'enclos', accountId: account.accountId,
          identity: { primary: { key: 'enclos-person', normalize: value => value, authentication: 'verified', sensitivity: 'pii' } },
          subject: { stableId: sender.id },
          conversation: { kind: 'direct', id: incoming.conversation },
          contextBinding: { agentId: account.agentId, sessionKey, messageId: incoming.id,
            nativeChannelId: incoming.conversation, inboundEventKind: 'user_request' },
          event: { kind: 'message', authMode: 'inbound', mayPair: false },
          // The bridge authenticated this person before presenting the agent's
          // token. OpenClaw does not add another channel pairing database.
          policy: { dmPolicy: 'allowlist', groupPolicy: 'disabled' },
          allowFrom: [sender.id], useDefaultPairingStore: false,
          command: { allowTextCommands: true, hasControlCommand: isCommand },
        });
        assertAuthority();
        if (ingress.ingress?.admission !== 'dispatch' || !ingress.senderAccess?.allowed || !ingress.routeAccess?.allowed || ingress.activationAccess?.shouldSkip || ingress.commandAccess?.shouldBlockControlCommand) throw new Error('native channel ingress refused this message');
        const ctxPayload = channel.inbound.buildContext({
          channel: 'enclos', accountId: account.accountId,
          // OpenClaw's owner authority follows the sender (ADR 0077); the
          // name stays the person's.
          messageId: incoming.id, timestamp: Date.now(), from: sender.id,
          sender: { id: sender.id, name: incoming.person },
          // Bridge groups deliberately remain ordinary direct contexts per
          // member; the bridge owns their turns, not OpenClaw broadcast groups.
          conversation: { kind: 'direct', id: incoming.conversation, nativeChannelId: incoming.conversation },
          route: { agentId: account.agentId, accountId: account.accountId,
            routeSessionKey: sessionKey, dispatchSessionKey: sessionKey, persistedSessionKey: sessionKey, dmScope: 'per-account-channel-peer' },
          reply: { to: incoming.conversation, originatingTo: incoming.conversation, nativeChannelId: incoming.conversation, sourceReplyDeliveryMode: 'direct' },
          message: { body: incoming.text, rawBody: incoming.text, bodyForAgent: incoming.text, commandBody: incoming.text, inboundEventKind: 'user_request' },
          media,
          command: { kind: isCommand ? 'text-slash' : 'normal', body: incoming.text, authorized: isCommand && ingress.commandAccess?.authorized === true },
          channelIngress: ingress,
        });
        const typing = on => { if (!transport.closed) transport.write(message('typing', { conversation: incoming.conversation, on })); };
        const finishActivity = activity.begin(incoming);
        let failureReported = false;
        const reportFailure = () => {
          if (failureReported || execution.signal.aborted) return;
          assertAuthority();
          transport.send(incoming.conversation, 'The agent could not respond. Check its runtime logs before trying again.', { replyTo: incoming.id });
          failureReported = true;
        };
        const caller = { agentId: nativeRoute.agentId, live: true, assertAuthority };
        try { await outboundCaller.run(caller, () => channel.inbound.dispatch({
          cfg, channel: 'enclos', accountId: account.accountId,
          route: { agentId: account.agentId, sessionKey, dmScope: 'per-account-channel-peer' },
          ctxPayload, messageId: incoming.id, assertAuthority,
          replyOptions: { abortSignal: execution.signal },
          dispatcherOptions: { onReplyStart: () => typing(true), onIdle: () => typing(false), onCleanup: () => typing(false) },
          delivery: {
            onError: reportFailure,
            async deliver(payload) {
            assertAuthority();
            // Preserve the complete native fallback for batches, forms and
            // presentations that this channel cannot faithfully control.
            if (sdk.renderPayload) payload = await sdk.renderPayload(payload);
            assertAuthority();
            const urls = [...new Set([...(payload.mediaUrl ? [payload.mediaUrl] : []), ...(payload.mediaUrls ?? [])])];
            if (urls.length && !hasMedia) throw new Error('enclos OpenClaw channel media is not enabled');
            return withStagedMedia(account, urls, { sdk, cfg, assertCurrent: assertAuthority }, attachments => {
              assertAuthority();
              if (payload.text || attachments.length) return { messageId: transport.send(incoming.conversation, payload.text ?? '',
                { replyTo: incoming.id, attachments, ...(payload.isStatusNotice ? { kind: 'status' } : {}) }) };
            });
          } },
        })); } catch (error) {
          reportFailure();
          // Native dispatch may have started work before failing. Preserve the
          // uncertain receipt so reconnects cannot replay that work.
          throw error;
        } finally { caller.live = false; finishActivity(); typing(false); void titles?.refresh(incoming.conversation); }
        } finally { execution.finish(); }
      },
    });
    activity = createActivity(transport, () => assertCurrent(ctx.cfg, account, transport));
    running.set(account.accountId, { transport, channel, account, cfg: ctx.cfg, sessionKeyFor, peekSessionKey });
    const stop = async () => {
      if (running.get(account.accountId)?.transport === transport) running.delete(account.accountId);
      for (const [key, turn] of sessionRoutes) if (turn.active?.transport === transport) sessionRoutes.delete(key);
      // Account authority ends first. Cleanup of one controller cannot prevent
      // another from revoking its native contexts and process-local bindings.
      for (const controller of controllers()) { try { controller.close?.(); } catch { /* Authority is already revoked. */ } }
      await transport.close();
      ctx.setStatus?.({ accountId: account.accountId, running: false, connected: false });
    };
    try {
      titles = createNativeTitles(runtime, account, transport, { currentConfig: () => currentConfig(ctx.cfg),
        assertCurrent: () => assertCurrent(ctx.cfg, account, transport), sessionKeyFor });
      approvals = sdk.nativeApprovals?.attach(account, transport, { cfg: ctx.cfg, channelRuntime: channel, abortSignal: ctx.abortSignal, sandbox: process.env.ENCLOS_SANDBOX, log: ctx.log,
        assertCurrent: () => assertCurrent(ctx.cfg, account, transport), sessionKeyFor });
      await transport.start();
      ctx.setStatus?.({ accountId: account.accountId, running: true, connected: true });
      if (ctx.abortSignal.aborted) return;
      await new Promise(resolve => ctx.abortSignal.addEventListener('abort', resolve, { once: true }));
    } finally { await stop(); }
  }

  async function sendText(ctx) {
    const account = resolveAccount(ctx.cfg, ctx.accountId);
    const active = running.get(account.accountId);
    if (!active) throw new Error('enclos account is not running');
    ctx.signal?.throwIfAborted();
    await ctx.onPlatformSendDispatch?.();
    ctx.assertDirectAdapterHandoff?.();
    ctx.signal?.throwIfAborted();
    assertCurrent(ctx.cfg, account, active.transport);
    const to = target(ctx.to, { ...account, home: active.transport.home });
    const id = active.transport.send(to, ctx.text, { ...(ctx.replyToId ? { replyTo: ctx.replyToId } : {}) });
    return { channel: 'enclos', to, messageId: id };
  }

  async function sendMedia(ctx) {
    if (!hasMedia) throw new Error('native media support is unavailable');
    const account = resolveAccount(ctx.cfg, ctx.accountId), active = running.get(account.accountId);
    if (!active) throw new Error('enclos account is not running');
    const assertAuthority = () => { ctx.signal?.throwIfAborted(); ctx.assertDirectAdapterHandoff?.(); assertCurrent(ctx.cfg, account, active.transport); };
    assertAuthority();
    return withStagedMedia(account, [ctx.mediaUrl], { sdk, cfg: ctx.cfg, access: ctx, assertCurrent: assertAuthority }, async attachments => {
      await ctx.onPlatformSendDispatch?.();
      assertAuthority();
      const to = target(ctx.to, { ...account, home: active.transport.home });
      const id = active.transport.send(to, ctx.text ?? '', { attachments, ...(ctx.replyToId ? { replyTo: ctx.replyToId } : {}) });
      return { channel: 'enclos', to, messageId: id };
    });
  }

  const plugin = {
    id: 'enclos',
    meta: { id: 'enclos', label: 'enclos app', selectionLabel: 'enclos app', docsPath: '/channels/enclos', blurb: 'Conversations through the host\'s enclos bridge.' },
    capabilities: { chatTypes: ['direct'], media: hasMedia, nativeCommands: false, blockStreaming: false, reply: true },
    ...(sdk.nativeApprovals ? { approvalCapability: sdk.nativeApprovals.approvalCapability } : {}),
    reload: { configPrefixes: ['channels.enclos', 'bindings'] },
    config: {
      listAccountIds: cfg => Object.keys(cfg.channels?.enclos?.accounts ?? {}).sort(),
      resolveAccount,
      inspectAccount(cfg, id) {
        try { const a = resolveAccount(cfg, id); return { accountId: a.accountId, enabled: a.enabled, configured: true }; }
        catch { return { accountId: id, enabled: false, configured: false }; }
      },
      isEnabled: account => account.enabled,
      isConfigured(account) { readToken(account.tokenFile); return true; },
      describeAccount: account => ({ accountId: account.accountId, enabled: account.enabled, configured: true }),
    },
    gateway: { startAccount },
    outbound: { deliveryMode: 'direct', textChunkLimit: 8000, sendText, ...(hasMedia ? { sendMedia } : {}) },
    messaging: {
      targetPrefixes: ['enclos'], targetIdComparison: 'case-sensitive',
      targetResolver: {
        hint: 'Use home or a known bridge conversation id for this account.',
        async resolveTarget(params) {
          // The current upstream target resolver has no agent field. A
          // resolver invoked during native dispatch inherits that caller.
          const caller = outboundCaller.getStore();
          if (caller && (!caller.live || (params.agentId != null && params.agentId !== caller.agentId))) return undefined;
          caller?.assertAuthority();
          const agentId = params.agentId ?? caller?.agentId;
          if (!agentId) return undefined;
          const route = await plugin.messaging.resolveOutboundSessionRoute({ ...params,
            agentId, target: params.normalized });
          return route ? { to: route.to, kind: 'user' } : undefined;
        },
      },
      normalizeTarget(raw) { try { return checkedId(raw.startsWith('enclos:') ? raw.slice(7) : raw); } catch { return undefined; } },
      inferTargetChatType: () => 'direct',
      resolveInboundAttachmentRoots: ({ cfg, accountId }) => [path.join(path.dirname(resolveAccount(cfg, accountId).socket), 'media')],
      async resolveOutboundSessionRoute(params) {
        const account = resolveAccount(params.cfg, params.accountId);
        if (account.agentId !== params.agentId) return null;
        const active = running.get(account.accountId);
        if (!active) return null;
        assertCurrent(params.cfg, account, active.transport);
        const to = target(params.target, { ...account, home: active.transport.home });
        const saved = active.transport.state.routes[to] ?? (to === active.transport.home ? active.transport.homeRoute() : undefined);
        // First-use Home owns a dedicated native session without asserting a
        // human identity. Other destinations need their known ownership route.
        if (!saved) return null;
        const sessionKey = active.channel.routing.buildAgentSessionKey({ agentId: account.agentId, channel: 'enclos', accountId: account.accountId,
          peer: { kind: 'direct', id: saved.peer }, dmScope: 'per-account-channel-peer' });
        return { sessionKey, baseSessionKey: sessionKey, recipientSessionExact: true,
          peer: { kind: 'direct', id: to }, chatType: 'direct', from: saved.person ?? `enclos:${account.accountId}`, to };
      },
    },
    conversationBindings: { supportsCurrentConversationBinding: false },
    agentPrompt: {
      inboundFormattingHints: () => ({ text_markup: 'markdown', rules: [
        'The person is using the enclos mobile app. Use CommonMark, fenced code and narrow tables.',
        hasMedia ? 'For a file, write it to a permitted local path and send MEDIA:/absolute/path/file. Images and files travel through the app channel, never a host URL.' : 'This channel currently sends text. Do not claim a file was delivered.',
        'For a static HTML artefact, use a self-contained UTF-8 .html file with inline CSS and data images/fonts. Scripts, remote assets, forms and automatic navigation are unavailable; deliberate HTTP(S) links open the browser.',
        'If sandbox policy refuses access, request the exact access with enclos_request_access when available. A request grants nothing; wait for approval and updated policy.',
        'Remote markdown images are links; HTML in text is literal. Home is the bridge-owned permanent destination for output without another conversation.',
        'Preserve complete native question prompts and follow the native tool result. Do not invent mobile question buttons or successful answer receipts. Secrets must use the native trusted Control UI, never chat.',
      ] }),
    },
  };
  return { plugin, setRuntime, registerFull, running, routines, models };
}
