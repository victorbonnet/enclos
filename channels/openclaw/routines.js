// Read-only native cron observations through the public Gateway service lease.
// No Gateway operator actor, native data-file write, or second scheduler.
import { createHash } from 'node:crypto';
import { checkedId, message, ProtocolError } from './protocol.js';

const MAX_JOBS = 2048;
const MAX_REPLY = 44 * 1024;
const PAGE_SIZE = 25;
const knownControls = new Set(['list', 'get', 'create', 'update', 'delete', 'set_enabled', 'run']);
const fail = (code, text) => { throw new ProtocolError(code, text); };
const identifier = (value, name) => {
  try { return checkedId(value, name); }
  catch { fail('bad_message', `Invalid ${name ?? 'request'} identifier.`); }
};
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const bounded = (value, bytes) => {
  let result = '', size = 0;
  for (const char of String(value ?? '').replace(/[\x00-\x1f\x7f-\x9f]/gu, ' ').trim()) {
    const next = Buffer.byteLength(char);
    if (size + next > bytes) break;
    result += char;
    size += next;
  }
  return result;
};
function timestamp(value) {
  const date = new Date(value);
  return Number.isFinite(value) && value >= 0 && Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function revision(job) {
  // Native execution progress is observational and must not move this revision.
  const { state: _state, createdAtMs: _created, updatedAtMs: _updated, ...definition } = job;
  return hash(definition);
}

function schedule(job, timezone) {
  const native = job.schedule;
  if (native?.kind === 'cron' && typeof native.expr === 'string' && native.expr.trim() && Buffer.byteLength(native.expr) <= 128) {
    if (native.tz && native.tz !== timezone) fail('unsupported', 'A routine has its own time zone. Manage this schedule in OpenClaw.');
    return { kind: 'cron', expression: native.expr };
  }
  if (native?.kind === 'every' && Number.isSafeInteger(native.everyMs) && native.everyMs % 60000 === 0 && native.everyMs >= 60000 && native.everyMs / 60000 <= 525600) {
    return { kind: 'interval', minutes: native.everyMs / 60000 };
  }
  if (native?.kind === 'at' && typeof native.at === 'string' && Buffer.byteLength(native.at) <= 128 && Number.isFinite(Date.parse(native.at))) {
    return { kind: 'once', at: native.at };
  }
  fail('unsupported', 'A native routine has a schedule this app cannot represent. Manage it in OpenClaw.');
}

function prompt(job) {
  const payload = job.payload;
  const text = payload?.kind === 'agentTurn' ? payload.message : payload?.kind === 'systemEvent' ? payload.text : undefined;
  if (typeof text !== 'string' || !text.trim() || text.includes('\0') || Buffer.byteLength(text) > 8192) {
    fail('unsupported', 'OpenClaw did not expose a complete instruction this app can display. Manage its details in OpenClaw.');
  }
  return text;
}

function exactText(value, field) {
  if (value == null) return undefined;
  if (typeof value !== 'string' || value.includes('\0') || Buffer.byteLength(value) > 512) {
    fail('unsupported', `OpenClaw exposed a ${field} this app cannot display completely.`);
  }
  return value;
}

function delivery(job, account, allowed) {
  const native = job.delivery;
  if (!native || native.mode === 'none') return { label: 'OpenClaw output', conversation: undefined };
  if (native.mode === 'announce' && native.channel === 'enclos' && native.accountId === account.accountId && allowed.includes(native.to)) {
    return { label: native.to, conversation: native.to };
  }
  return { label: `${bounded(native.channel ?? 'OpenClaw', 100)} · native delivery`, conversation: undefined };
}

function summary(job, account, allowed, timezone, automatic) {
  identifier(job.id, 'routine');
  const output = delivery(job, account, allowed);
  const text = job.payload?.kind === 'agentTurn' ? job.payload.message : job.payload?.text;
  return {
    id: job.id, revision: revision(job), ...(job.name ? { name: bounded(job.name, 512) } : {}),
    schedule: schedule(job, timezone), enabled: job.enabled === true,
    prompt_preview: typeof text === 'string' ? bounded(text, 512) : 'Instructions managed in OpenClaw',
    delivery_label: output.label, editable: false,
    ...(job.state?.runningAtMs ? { state: 'running' } : automatic === false && job.enabled === true
      ? { state: 'paused', paused_reason: 'Automatic scheduling is disabled in OpenClaw.' } : {}),
    ...(timestamp(job.state?.nextRunAtMs) ? { next_run_at: timestamp(job.state.nextRunAtMs) } : {}),
    ...(timestamp(job.state?.lastRunAtMs) ? { last_run_at: timestamp(job.state.lastRunAtMs) } : {}),
    ...(job.state?.lastRunStatus ? { last_status: bounded(job.state.lastRunStatus, 128) } : {}),
    ...(job.state?.lastError ? { last_error: bounded(job.state.lastError, 512) } : {}),
  };
}

export class RoutineInventory {
  constructor({ timezone = () => Intl.DateTimeFormat().resolvedOptions().timeZone } = {}) {
    this.timezone = timezone;
    this.generation = 0;
    this.context = null;
  }
  start(context) { this.context = context; this.generation += 1; }
  stop() { this.context = null; this.generation += 1; }
  available() {
    try { return typeof this.context?.getCron?.()?.list === 'function'; }
    catch { return false; }
  }
  register(api) {
    if (typeof api.registerService !== 'function') return;
    api.registerService({ id: 'enclos-routines', start: context => this.start(context), stop: () => this.stop() });
  }

  async handle(control, { account, assertCurrent, write }) {
    identifier(control.id);
    if (!knownControls.has(control.action)) fail('bad_message', 'Unknown routine control.');
    // Refuse mutations without even entering the native list/read seam.
    if (!['list', 'get'].includes(control.action)) fail('unsupported', 'Routine changes are unavailable in this app. Manage them in OpenClaw.');
    const generation = this.generation;
    const context = this.context;
    assertCurrent();
    let cron;
    try { cron = context?.getCron?.(); } catch { /* A stopped native lease is unavailable. */ }
    if (!cron || typeof cron.list !== 'function') fail('agent_unavailable', 'OpenClaw routines are not available. Reconnect and refresh.');
    const current = () => {
      assertCurrent();
      if (generation !== this.generation || context !== this.context || context.getCron() !== cron) fail('agent_unavailable', 'The native scheduler changed. Reconnect and refresh.');
    };
    let jobs, automatic;
    try {
      jobs = await cron.list({ includeDisabled: true });
      current();
      if (typeof cron.isEnabled === 'function') { automatic = await cron.isEnabled(); current(); }
    } catch (error) {
      if (error instanceof ProtocolError) throw error;
      fail('agent_unavailable', 'OpenClaw routines could not be read. Reconnect and refresh.');
    }
    if (!Array.isArray(jobs) || jobs.length > MAX_JOBS) fail('unsupported', 'OpenClaw returned an unsupported or oversized routine inventory.');
    const own = jobs.filter(job => job && job.agentId === account.agentId).sort((a, b) => String(a.id).localeCompare(String(b.id), 'en'));
    const timezone = this.timezone();
    if (typeof timezone !== 'string' || !timezone || Buffer.byteLength(timezone) > 128) fail('unsupported', 'The native scheduling time zone is unavailable.');
    const allowed = Array.isArray(control.allowed_deliveries) && control.allowed_deliveries.every(value => typeof value === 'string') ? control.allowed_deliveries : [];
    let response;
    if (control.action === 'get') {
      identifier(control.routine, 'routine');
      const job = own.find(job => job.id === control.routine);
      if (!job) fail('not_found', 'This agent no longer has that routine.');
      const found = summary(job, account, allowed, timezone, automatic);
      const output = delivery(job, account, allowed);
      const name = exactText(job.name, 'name'), model = exactText(job.payload?.model, 'model');
      const definition = { ...(name ? { name } : {}), prompt: prompt(job), schedule: found.schedule,
        ...(output.conversation ? { delivery: output.conversation } : {}), skills: [], script_only: false,
        ...(model ? { model } : {}) };
      response = message('routine.response', { of: control.id, result: 'routine', routine: { ...found, definition } });
    } else {
      const routines = own.map(job => summary(job, account, allowed, timezone, automatic));
      const fingerprint = hash(routines.map(job => [job.id, job.revision])).slice(0, 32);
      let offset = 0;
      if (control.cursor != null) {
        try {
          checkedId(control.cursor, 'cursor');
          const saved = JSON.parse(Buffer.from(control.cursor, 'base64url').toString());
          if (!Array.isArray(saved) || saved.length !== 2 || saved[0] !== fingerprint || !Number.isSafeInteger(saved[1]) || saved[1] < 0 || saved[1] > routines.length) throw new Error();
          offset = saved[1];
        } catch { fail('conflict', 'The routine inventory changed. Refresh before reading the next page.'); }
      }
      let end = Math.min(offset + PAGE_SIZE, routines.length);
      response = message('routine.response', { of: control.id, result: 'list', routines: routines.slice(offset, end),
        ...(end < routines.length ? { next_cursor: Buffer.from(JSON.stringify([fingerprint, end])).toString('base64url') } : {}),
        options: { timezone, operations: ['get'], features: [], skills: [], models: [], toolsets: [] }, deliveries: [], deliveries_limited: false });
      while (Buffer.byteLength(JSON.stringify(response)) > MAX_REPLY && end > offset + 1) {
        end -= 1;
        response.routines = routines.slice(offset, end);
        response.next_cursor = Buffer.from(JSON.stringify([fingerprint, end])).toString('base64url');
      }
    }
    if (Buffer.byteLength(JSON.stringify(response)) > MAX_REPLY) fail('unsupported', 'The native routine reply is too large to display safely.');
    current();
    write(response); // Live correlated response; never persisted for replay.
  }
}
