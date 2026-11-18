// The agent's model, read and changed from the app (`model.request`).
// OpenClaw keeps it: its own catalogue (`buildModelsProviderData`, what its
// `/models` picker shows) lists the providers and their models, and its own
// config write saves the agent's `agents.entries.<id>.model.primary`, which
// OpenClaw checks against its catalogue and the Gateway hot-applies.
import { createHash } from 'node:crypto';
import { message, ProtocolError } from './protocol.js';

export const MAX_PROVIDERS = 100;
export const MAX_MODELS = 300;
const MAX_ID = 200;
const MAX_LABEL = 200;
const MAX_SETUP = 500;
const MAX_REPLY = 44 * 1024;
const fail = (code, text) => { throw new ProtocolError(code, text); };

// The bridge's hidden characters (enclos-protocol `visible`), joiners
// always counted: an id or label holding one is left out, never sent.
const HIDDEN = /[\p{Cc}\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\ue000-\uf8ff\ufdd0-\ufdef\u{e0000}-\u{e0fff}\u{f0000}-\u{10ffff}]/u;
const nonCharacter = value => [...value].some(c => (c.codePointAt(0) & 0xfffe) === 0xfffe);
export const visible = value => typeof value === 'string' && !HIDDEN.test(value) && !nonCharacter(value);

const id = value => typeof value === 'string' && value.trim() && Buffer.byteLength(value) <= MAX_ID && visible(value) ? value : undefined;
const label = (value, fallback) => {
  if (typeof value !== 'string' || !value.trim() || !visible(value)) return fallback;
  let result = '', size = 0;
  for (const char of value.trim()) {
    size += Buffer.byteLength(char);
    if (size > MAX_LABEL) break;
    result += char;
  }
  return result;
};
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value ?? null))).digest('hex').slice(0, 32);

export function validateModelRequest(control) {
  if (control.action === 'options') return;
  if (control.action === 'models') { if (!id(control.provider)) fail('bad_message', 'provider is not an id'); return; }
  if (control.action === 'set') {
    for (const key of ['provider', 'model', 'revision']) if (!id(control[key])) fail('bad_message', `${key} is not an id`);
    return;
  }
  fail('bad_message', 'Unknown model request.');
}

// `provider/model`, split at the first slash: a model id may hold more.
function split(ref) {
  if (typeof ref !== 'string') return undefined;
  const at = ref.indexOf('/');
  if (at <= 0 || at === ref.length - 1) return undefined;
  const provider = id(ref.slice(0, at)), model = id(ref.slice(at + 1));
  return provider && model ? { provider, model } : undefined;
}

// What the agent's own entry says, else the shared default.
function configured(cfg, agentId) {
  const entry = cfg?.agents?.entries?.[agentId]?.model ?? cfg?.agents?.defaults?.model;
  return typeof entry === 'string' ? entry : entry?.primary;
}

export class ModelSettings {
  constructor({ catalogue, runtime }) {
    this.catalogue = catalogue;
    this.runtime = runtime;
  }

  available() {
    try {
      const config = this.runtime()?.config;
      return typeof this.catalogue === 'function' && typeof config?.current === 'function' && typeof config.mutateConfigFile === 'function';
    } catch { return false; }
  }

  revision(cfg, agentId) {
    return hash([cfg?.agents?.entries?.[agentId]?.model, cfg?.agents?.defaults?.model]);
  }

  // OpenClaw's view of every provider (`all`) and of those the agent can
  // use now (`default`, auth-backed).
  async views(cfg, agentId) {
    const [all, usable] = await Promise.all([this.catalogue(cfg, agentId, { view: 'all' }), this.catalogue(cfg, agentId, { view: 'default' })]);
    return { all, usable };
  }

  setup(all, provider, agentId) {
    const notice = all?.modelMenu?.byProvider?.get?.(provider)?.notice;
    const how = `run \`openclaw models auth login --provider ${provider} --agent ${agentId}\` in an \`enclos connect\` session on the host`;
    const text = typeof notice === 'string' && notice.trim() && visible(notice.replace(/\n/gu, ' '))
      ? `${notice.replace(/\n/gu, ' ').trim()} Set it up on the host: ${how}.` : `Set it up on the host: ${how}.`;
    return Buffer.byteLength(text) <= MAX_SETUP ? text : `Set it up on the host: ${how}.`;
  }

  isUsable(usable, provider) {
    return (usable?.byProvider?.get?.(provider)?.size ?? 0) > 0;
  }

  async handle(control, { account, assertCurrent, write }) {
    validateModelRequest(control);
    const runtime = this.runtime();
    if (!this.available()) fail('unsupported', 'Choosing the model is unavailable in this OpenClaw.');
    const agentId = account.agentId;
    let response;
    try {
      response = await this.answer(control, runtime, agentId, assertCurrent);
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      fail('unknown', 'The outcome is unknown: open the agent\'s model again before retrying.');
    }
    if (Buffer.byteLength(JSON.stringify(response)) > MAX_REPLY) fail('unsupported', 'OpenClaw\'s model list is too large to show on the phone.');
    assertCurrent();
    write(response); // Live correlated response; never persisted for replay.
  }

  async answer(control, runtime, agentId, assertCurrent) {
    const cfg = runtime.config.current();
    if (control.action === 'options') {
      const { all, usable } = await this.views(cfg, agentId);
      assertCurrent();
      const providers = [];
      for (const provider of all.providers ?? []) {
        if (!id(provider) || providers.some(p => p.id === provider)) continue;
        const ok = this.isUsable(usable, provider);
        providers.push({ id: provider, label: provider, usable: ok, ...(ok ? {} : { setup: this.setup(all, provider, agentId) }) });
        if (providers.length === MAX_PROVIDERS) break;
      }
      const current = split(configured(cfg, agentId)) ?? split(`${all.resolvedDefault?.provider}/${all.resolvedDefault?.model}`);
      return message('model.response', { of: control.id, result: 'options', ...(current ? { current } : {}),
        revision: this.revision(cfg, agentId), applies: 'live', providers, custom_models: false });
    }
    if (control.action === 'models') {
      const { all } = await this.views(cfg, agentId);
      const listed = all.byProvider?.get?.(control.provider);
      if (!listed) fail('not_found', 'OpenClaw does not list that provider.');
      const models = [];
      for (const model of [...listed].sort((a, b) => String(a).localeCompare(String(b), 'en'))) {
        if (!id(model)) continue;
        models.push({ id: model, label: label(all.modelNames?.get?.(`${control.provider}/${model}`), model) });
      }
      let reply = message('model.response', { of: control.id, result: 'models', provider: control.provider,
        models: models.slice(0, MAX_MODELS), limited: models.length > MAX_MODELS });
      while (Buffer.byteLength(JSON.stringify(reply)) > MAX_REPLY && reply.models.length > 1) {
        reply.models = reply.models.slice(0, Math.floor(reply.models.length * 0.9));
        reply.limited = true;
      }
      return reply;
    }
    return this.set(control, runtime, cfg, agentId, assertCurrent);
  }

  async set(control, runtime, cfg, agentId, assertCurrent) {
    if (this.revision(cfg, agentId) !== control.revision) fail('conflict', 'The agent\'s model changed since it was read. Open it again.');
    const { all, usable } = await this.views(cfg, agentId);
    const listed = all.byProvider?.get?.(control.provider);
    if (!listed) fail('not_found', 'OpenClaw does not list that provider.');
    if (!this.isUsable(usable, control.provider)) fail('not_allowed', `The agent cannot use ${control.provider} yet. ${this.setup(all, control.provider, agentId)}`);
    if (!listed.has(control.model)) fail('not_found', 'OpenClaw does not list that model for this provider.');
    const previous = split(configured(cfg, agentId));
    assertCurrent();
    const ref = `${control.provider}/${control.model}`;
    const written = await runtime.config.mutateConfigFile({
      afterWrite: { mode: 'auto' },
      writeOptions: { assertCurrent },
      mutate: draft => {
        // Checked again on the draft: another writer may have changed it.
        if (this.revision(draft, agentId) !== control.revision) fail('conflict', 'The agent\'s model changed since it was read. Open it again.');
        draft.agents ??= {};
        draft.agents.entries ??= {};
        const entry = draft.agents.entries[agentId] ??= {};
        if (entry.model && typeof entry.model === 'object') entry.model.primary = ref;
        else entry.model = { primary: ref };
      },
    });
    const next = written?.nextConfig ?? runtime.config.current();
    const current = split(configured(next, agentId)) ?? { provider: control.provider, model: control.model };
    const applies = written?.followUp?.requiresRestart ? 'restart' : 'live';
    return message('model.response', { of: control.id, result: 'set', ...(previous ? { previous } : {}), current,
      revision: this.revision(next, agentId), applies });
  }
}
