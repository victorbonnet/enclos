// The agent's model, read and changed from the app (`model.request`).
// OpenClaw keeps it: its own catalogue (`buildModelsProviderData`, what its
// `/models` picker shows) lists the model providers and their models, and
// the plugin takes only a model it lists. The agent's primary model is
// saved through OpenClaw's own config write, which validates the config;
// OpenClaw's reload rules hot-apply agent settings (read in its source,
// 2026.11.3; to verify on a host, enclos design, section 14).
import { createHash } from 'node:crypto';
import { message, ProtocolError } from './protocol.js';

export const MAX_PROVIDERS = 100;
export const MAX_MODELS = 300;
const MAX_ID = 200;
const MAX_LABEL = 200;
const MAX_SETUP = 500;
// The most bytes of a `model.response` line (enclos_protocol::model::MAX_REPLY_BYTES):
// under the bridge's 60 KiB device-message budget, with room for its envelope.
const MAX_REPLY = 44 * 1024;
const UNKNOWN = 'The outcome is unknown: open the agent\'s model again before retrying.';
const fail = (code, text) => { throw new ProtocolError(code, text); };
const log = (text, error) => console.error(`[enclos] ${text}`, error ?? '');

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
const hash = value => createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex').slice(0, 32);
const size = value => Buffer.byteLength(JSON.stringify(value));

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

const primary = model => typeof model === 'string' ? model : model?.primary;

// The agent's own settings, in whichever roster the config has: OpenClaw
// reads `agents.entries` (by id) and, only without it, the older
// `agents.list`. Undefined when the agent has none.
export function agentEntry(cfg, agentId) {
  const agents = cfg?.agents;
  if (agents?.entries && typeof agents.entries === 'object' && !Array.isArray(agents.entries)) return agents.entries[agentId];
  if (Array.isArray(agents?.list)) return agents.list.find(entry => entry?.id === agentId);
  return undefined;
}

// The agent's model reference: its own, else the shared default.
function configured(cfg, agentId) {
  return primary(agentEntry(cfg, agentId)?.model) ?? primary(cfg?.agents?.defaults?.model);
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
    } catch (error) {
      log('the model capability is off: OpenClaw\'s runtime could not be read', error);
      return false;
    }
  }

  // The model references alone, so that a config read as the runtime
  // resolves it and the one OpenClaw's write edits agree.
  revision(cfg, agentId) {
    return hash([primary(agentEntry(cfg, agentId)?.model) ?? null, primary(cfg?.agents?.defaults?.model) ?? null]);
  }

  // OpenClaw's view of every model provider (`all`) and of those the agent
  // can use now (`default`: signed in, and within its model allowlist).
  async views(cfg, agentId) {
    const [all, usable] = await Promise.all([this.catalogue(cfg, agentId, { view: 'all' }), this.catalogue(cfg, agentId, { view: 'default' })]);
    for (const view of [all, usable]) {
      if (!Array.isArray(view?.providers) || !(view.byProvider instanceof Map)) {
        fail('unsupported', 'This OpenClaw\'s model catalogue has a shape the app does not read. Nothing was changed.');
      }
    }
    return { all, usable };
  }

  setup(all, provider, agentId) {
    const notice = all?.modelMenu?.byProvider?.get?.(provider)?.notice;
    const how = `sign it in with \`openclaw models auth login --provider ${provider} --agent ${agentId}\` in an \`enclos connect\` session, or allow it in the agent's model settings, on the host`;
    const said = typeof notice === 'string' ? notice.replace(/\n/gu, ' ').trim() : '';
    const text = said && visible(said) ? `${said} To use it, ${how}.` : `To use it, ${how}.`;
    return Buffer.byteLength(text) <= MAX_SETUP ? text : `To use it, ${how}.`;
  }

  isUsable(usable, provider) {
    return (usable.byProvider.get(provider)?.size ?? 0) > 0;
  }

  async handle(control, { account, assertCurrent, write }) {
    validateModelRequest(control);
    if (!this.available()) fail('unsupported', 'Choosing the model is unavailable in this OpenClaw.');
    const runtime = this.runtime();
    const agentId = account.agentId;
    const state = { writing: false };
    let response;
    try {
      response = await this.answer(control, runtime, agentId, assertCurrent, state);
      if (size(response) > MAX_REPLY) fail('unsupported', 'OpenClaw\'s answer is too large to show on the phone. See it on the host.');
      assertCurrent();
      write(response); // Live correlated response; never persisted for replay.
    } catch (error) {
      if (error instanceof ProtocolError && !(state.writing && error.code === 'agent_unavailable')) throw error;
      log(`the agent's model request (${control.action}) failed`, error);
      // Once the write started, a change may have been made: never one the
      // device would take as safe to try again.
      if (state.writing) fail('unknown', UNKNOWN);
      fail('agent_unavailable', `OpenClaw could not read the agent's models (${error?.name ?? 'error'}). Nothing was changed.`);
    }
  }

  async answer(control, runtime, agentId, assertCurrent, state) {
    const cfg = runtime.config.current();
    if (control.action === 'options') {
      const { all, usable } = await this.views(cfg, agentId);
      assertCurrent();
      const providers = [];
      for (const provider of all.providers) {
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
      const listed = all.byProvider.get(control.provider);
      if (!listed) fail('not_found', 'OpenClaw does not list that model provider.');
      const models = [];
      for (const model of [...listed].sort((a, b) => String(a).localeCompare(String(b), 'en'))) {
        if (!id(model)) continue;
        models.push({ id: model, label: label(all.modelNames?.get?.(`${control.provider}/${model}`), model) });
      }
      const reply = message('model.response', { of: control.id, result: 'models', provider: control.provider,
        models: models.slice(0, MAX_MODELS), limited: models.length > MAX_MODELS });
      while (size(reply) > MAX_REPLY && reply.models.length > 1) {
        reply.models = reply.models.slice(0, Math.floor(reply.models.length * 0.9));
        reply.limited = true;
      }
      return reply;
    }
    return this.set(control, runtime, cfg, agentId, assertCurrent, state);
  }

  async set(control, runtime, cfg, agentId, assertCurrent, state) {
    if (this.revision(cfg, agentId) !== control.revision) fail('conflict', 'The agent\'s model changed since it was read. Open it again.');
    const { all, usable } = await this.views(cfg, agentId);
    const listed = all.byProvider.get(control.provider);
    if (!listed) fail('not_found', 'OpenClaw does not list that model provider.');
    if (!this.isUsable(usable, control.provider)) fail('not_allowed', `The agent cannot use ${control.provider} yet. ${this.setup(all, control.provider, agentId)}`);
    if (!listed.has(control.model)) fail('not_found', 'OpenClaw does not list that model for this model provider.');
    const previous = split(configured(cfg, agentId));
    assertCurrent();
    const ref = `${control.provider}/${control.model}`;
    // What the draft showed; refused after the write, never thrown from
    // inside it, whatever OpenClaw's writer does with an error there.
    let refused;
    state.writing = true;
    const written = await runtime.config.mutateConfigFile({
      afterWrite: { mode: 'auto' },
      writeOptions: { assertCurrent },
      mutate: draft => {
        // Checked again on the draft: another writer may have changed it.
        if (this.revision(draft, agentId) !== control.revision) { refused = 'conflict'; return; }
        draft.agents ??= {};
        const agents = draft.agents;
        let entry;
        if (agents.entries && typeof agents.entries === 'object' && !Array.isArray(agents.entries)) entry = agents.entries[agentId] ??= {};
        else if (Array.isArray(agents.list)) {
          entry = agents.list.find(item => item?.id === agentId);
          if (!entry) { refused = 'missing'; return; }
        } else entry = (agents.entries = {})[agentId] = {};
        if (entry.model && typeof entry.model === 'object') entry.model.primary = ref;
        else if (entry.model === undefined) {
          // An agent on the shared default keeps its fallbacks.
          const fallbacks = agents.defaults?.model?.fallbacks;
          entry.model = Array.isArray(fallbacks) ? { primary: ref, fallbacks: [...fallbacks] } : { primary: ref };
        } else entry.model = { primary: ref };
      },
    });
    state.writing = false;
    if (refused === 'conflict') fail('conflict', 'The agent\'s model changed while it was being saved. Open it again.');
    if (refused === 'missing') fail('unsupported', 'The agent is not in OpenClaw\'s agent list. Set its model on the host.');
    const next = written?.nextConfig ?? runtime.config.current();
    const current = split(configured(next, agentId));
    if (!current || current.provider !== control.provider) {
      log(`the agent's model was saved as ${ref} but reads back as ${configured(next, agentId)}`);
      fail('unknown', 'Saved, but the agent\'s model could not be read back. Open it again.');
    }
    const applies = written?.followUp?.requiresRestart === true ? 'restart' : 'live';
    // A failure from here on is after the change: never safe to retry.
    state.writing = true;
    return message('model.response', { of: control.id, result: 'set', ...(previous ? { previous } : {}), current,
      revision: this.revision(next, agentId), applies });
  }
}
