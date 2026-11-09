// OpenClaw 2026.11.2 public channel contract. Native imports live in index.js.
import { createHash } from 'node:crypto';
import path from 'node:path';
import { ChannelTransport, readToken } from './transport.js';
import { checkedId } from './protocol.js';

export const TESTED_OPENCLAW = '2026.11.2';
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
    tokenFile: value.tokenFile, home: value.home,
    stateDir: value.stateDir ?? path.join(path.dirname(value.socket), 'openclaw-state'),
    enabled: section?.enabled !== false && value.enabled !== false,
  };
}

export function sessionPeer(conversation, person) {
  checkedId(conversation, 'conversation'); checkedId(person, 'person');
  return createHash('sha256').update(JSON.stringify([conversation, person])).digest('hex');
}

function accountKey(account) { return JSON.stringify([account.accountId, account.agentId, account.socket, account.tokenFile, account.stateDir]); }
function target(raw, account) {
  const value = typeof raw === 'string' && raw.startsWith('enclos:') ? raw.slice(7) : raw;
  return checkedId(!value || value === 'home' ? account.home : value, 'conversation');
}

export function createChannel() {
  let runtime;
  const running = new Map();
  const currentConfig = fallback => runtime?.config?.current?.() ?? fallback;
  const assertCurrent = (cfg, account, transport) => {
    const now = resolveAccount(currentConfig(cfg), account.accountId);
    if (!now.enabled || accountKey(now) !== accountKey(account) || transport.closed || running.get(account.accountId)?.transport !== transport) {
      throw new Error('enclos channel account was stopped or reconfigured');
    }
  };

  function setRuntime(value) {
    // version is part of the installed public PluginRuntimeCore contract.
    if (value?.version !== TESTED_OPENCLAW) throw new Error(`enclos channel is tested with OpenClaw ${TESTED_OPENCLAW}; install a matching enclos channel before enabling it with ${value?.version ?? 'an unknown version'}`);
    runtime = value;
  }

  async function startAccount(ctx) {
    if (!runtime || runtime.version !== TESTED_OPENCLAW) throw new Error(`enclos requires the tested OpenClaw ${TESTED_OPENCLAW} plugin runtime`);
    const channel = ctx.channelRuntime ?? runtime.channel;
    if (!channel?.inbound?.ingress?.resolve || !channel.inbound.buildContext || !channel.inbound.dispatch || !channel.routing?.resolveAgentRoute || !channel.routing.buildAgentSessionKey) {
      throw new Error('OpenClaw did not supply its public channel ingress/dispatch runtime; update the enclos channel compatibility pair');
    }
    const account = resolveAccount(ctx.cfg, ctx.accountId);
    if (!account.enabled) throw new Error('enclos account is disabled');
    if (running.has(account.accountId)) throw new Error('enclos account is already running');
    let transport;
    transport = new ChannelTransport(account, {
      async onMessage(incoming, route) {
        const cfg = currentConfig(ctx.cfg);
        const assertAuthority = () => assertCurrent(cfg, account, transport);
        assertAuthority();
        const nativeRoute = channel.routing.resolveAgentRoute({ cfg, channel: 'enclos', accountId: account.accountId,
          peer: { kind: 'direct', id: incoming.conversation }, dmScope: 'per-account-channel-peer' });
        if (nativeRoute.agentId !== account.agentId || nativeRoute.matchedBy === 'default') throw new Error('enclos account needs an explicit native binding to its agent');
        const sessionKey = channel.routing.buildAgentSessionKey({ agentId: account.agentId, channel: 'enclos',
          accountId: account.accountId, peer: { kind: 'direct', id: route.peer }, dmScope: 'per-account-channel-peer' });
        const isCommand = channel.text?.hasControlCommand?.(incoming.text, cfg) ?? incoming.text.trimStart().startsWith('/');
        const ingress = await channel.inbound.ingress.resolve({
          channelId: 'enclos', accountId: account.accountId,
          identity: { primary: { key: 'enclos-person', normalize: value => value, authentication: 'verified', sensitivity: 'pii' } },
          subject: { stableId: incoming.person },
          conversation: { kind: 'direct', id: incoming.conversation },
          contextBinding: { agentId: account.agentId, sessionKey, messageId: incoming.id,
            nativeChannelId: incoming.conversation, inboundEventKind: 'user_request' },
          event: { kind: 'message', authMode: 'inbound', mayPair: false },
          // The bridge authenticated this person before presenting the agent's
          // token. OpenClaw does not add another channel pairing database.
          policy: { dmPolicy: 'allowlist', groupPolicy: 'disabled' },
          allowFrom: [incoming.person], useDefaultPairingStore: false,
          command: { allowTextCommands: true, hasControlCommand: isCommand },
        });
        assertAuthority();
        if (ingress.ingress?.admission !== 'dispatch' || !ingress.senderAccess?.allowed || !ingress.routeAccess?.allowed || ingress.activationAccess?.shouldSkip || ingress.commandAccess?.shouldBlockControlCommand) throw new Error('native channel ingress refused this message');
        const ctxPayload = channel.inbound.buildContext({
          channel: 'enclos', accountId: account.accountId,
          messageId: incoming.id, timestamp: Date.now(), from: incoming.person,
          sender: { id: incoming.person, name: incoming.person },
          // Bridge groups deliberately remain ordinary direct contexts per
          // member; the bridge owns their turns, not OpenClaw broadcast groups.
          conversation: { kind: 'direct', id: incoming.conversation, nativeChannelId: incoming.conversation },
          route: { agentId: account.agentId, accountId: account.accountId,
            routeSessionKey: sessionKey, dispatchSessionKey: sessionKey, persistedSessionKey: sessionKey, dmScope: 'per-account-channel-peer' },
          reply: { to: incoming.conversation, originatingTo: incoming.conversation, nativeChannelId: incoming.conversation, sourceReplyDeliveryMode: 'direct' },
          message: { body: incoming.text, rawBody: incoming.text, bodyForAgent: incoming.text, commandBody: incoming.text, inboundEventKind: 'user_request' },
          command: { kind: isCommand ? 'text-slash' : 'normal', body: incoming.text, authorized: isCommand && ingress.commandAccess?.authorized === true },
          channelIngress: ingress,
        });
        await channel.inbound.dispatch({
          cfg, channel: 'enclos', accountId: account.accountId,
          route: { agentId: account.agentId, sessionKey, dmScope: 'per-account-channel-peer' },
          ctxPayload, messageId: incoming.id, assertAuthority,
          delivery: { async deliver(payload) {
            assertAuthority();
            if (payload.mediaUrl || payload.mediaUrls?.length) throw new Error('enclos OpenClaw channel media is not enabled yet');
            if (payload.text) return { messageId: transport.send(incoming.conversation, payload.text,
              { replyTo: incoming.id, ...(payload.isStatusNotice ? { kind: 'status' } : {}) }) };
          } },
        });
      },
    });
    running.set(account.accountId, { transport, channel, account });
    const stop = async () => {
      if (running.get(account.accountId)?.transport === transport) running.delete(account.accountId);
      await transport.close();
      ctx.setStatus?.({ accountId: account.accountId, running: false, connected: false });
    };
    try {
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

  const plugin = {
    id: 'enclos',
    meta: { id: 'enclos', label: 'enclos app', selectionLabel: 'enclos app', docsPath: '/channels/enclos', blurb: 'Conversations through the host\'s enclos bridge.' },
    capabilities: { chatTypes: ['direct'], media: false, nativeCommands: false, blockStreaming: false, reply: true },
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
    outbound: { deliveryMode: 'direct', textChunkLimit: 8000, sendText },
    messaging: {
      targetPrefixes: ['enclos'], targetIdComparison: 'case-sensitive',
      normalizeTarget(raw) { try { return checkedId(raw.startsWith('enclos:') ? raw.slice(7) : raw); } catch { return undefined; } },
      inferTargetChatType: () => 'direct',
      async resolveOutboundSessionRoute(params) {
        const account = resolveAccount(params.cfg, params.accountId);
        if (account.agentId !== params.agentId) return null;
        const active = running.get(account.accountId);
        if (!active) return null;
        const to = target(params.target, account);
        const saved = active.transport.state.routes[to];
        // Unsolicited Home can be delivered without creating shared context.
        // Other outbound sessions need their known person/conversation route.
        if (!saved) return null;
        const sessionKey = active.channel.routing.buildAgentSessionKey({ agentId: account.agentId, channel: 'enclos', accountId: account.accountId,
          peer: { kind: 'direct', id: saved.peer }, dmScope: 'per-account-channel-peer' });
        return { sessionKey, baseSessionKey: sessionKey, recipientSessionExact: true,
          peer: { kind: 'direct', id: to }, chatType: 'direct', from: saved.person, to };
      },
    },
    conversationBindings: { supportsCurrentConversationBinding: false },
    agentPrompt: {
      inboundFormattingHints: () => ({ text_markup: 'markdown', rules: [
        'The person is using the enclos mobile app. Use CommonMark, fenced code and narrow tables.',
        'This channel currently sends text. Do not claim a file or interactive control was delivered.',
        'Remote markdown images are links; HTML in text is literal. Home is the bridge-owned permanent destination for output without another conversation.',
      ] }),
    },
  };
  return { plugin, setRuntime, running };
}
