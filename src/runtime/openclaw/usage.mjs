// What each OpenClaw agent used of its model providers, read inside the
// sandbox (issue #348, design §11, Usage).
//
// `enclos usage` runs this with OpenClaw's own Node, in the sandbox, as an
// exec session. It asks the sandbox's running gateway for each agent's
// `sessions.usage`, as OpenClaw's own Control UI does, and writes enclos's
// runtime-neutral usage report (format 1) to the file it is given, which
// enclos then reads on the host. The gateway counts from its per-agent
// databases with its own rules (the visible branch of each native chat,
// archived and cold chats included), which this reader does not repeat.
//
// Arguments: the report's path, the window's start (Unix seconds), then the
// agents' names. OpenClaw counts by day: the window starts at the UTC
// midnight of the day that holds the start, and a chat counts for what it
// used in those days. The token is resolved in this process's memory, as
// `enclos-openclaw-delete.mjs` does, never written or passed on.
//
// Whatever goes wrong is written into the report (`error`), never to the
// terminal: enclos sends this program's output nowhere.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export const FORMAT = 1;
const MAX_MODELS = 50;
const TOP_CHATS = 5;
// Native chats listed per agent, most recently active first, the top ones
// picked from; the per-model totals cover every chat in the window.
const LISTED_CHATS = 100;
const MAX_TEXT = 200;
const MINIMUM = '2026.11.5';
// What OpenClaw counts. It keeps no reasoning count of its own (reasoning is
// part of `output`), so `reasoning` is null, never 0.
const KEPT = ['calls', 'input', 'output', 'cache_read', 'cache_write'];

class Unread extends Error {}

function text(value) {
  if (value == null) return null;
  return [...String(value)].slice(0, MAX_TEXT).join('');
}

/** A count OpenClaw reported: a whole number of at least 0, else unknown. */
function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** A sum of money OpenClaw reported: finite and at least 0, else unknown. */
function amount(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function tokens(totals) {
  return {
    input: count(totals?.input),
    output: count(totals?.output),
    cache_read: count(totals?.cacheRead),
    cache_write: count(totals?.cacheWrite),
    reasoning: null,
  };
}

function total(t) {
  return (t.input ?? 0) + (t.output ?? 0) + (t.cache_read ?? 0) + (t.cache_write ?? 0);
}

/**
 * What OpenClaw says a model's calls cost. It estimates each call from its
 * own price table when it records it (a provider-billed figure replaces the
 * estimate, which a total cannot tell apart), so a known cost is
 * `estimated`; a call it could not price makes the sum `mixed`, or
 * `unknown` when no call was priced.
 */
function cost(totals, calls) {
  const usd = amount(totals?.totalCost);
  const missing = count(totals?.missingCostEntries) ?? 0;
  if (usd == null || (calls != null && missing >= calls)) return { usd: null, kind: 'unknown' };
  return { usd, kind: missing > 0 ? 'mixed' : 'estimated' };
}

/** The UTC day, `YYYY-MM-DD`, that holds `seconds`. */
export function day(seconds) {
  return new Date(seconds * 1000).toISOString().slice(0, 10);
}

/** One agent's answer from `sessions.usage`, as format 1 lists it. */
export function agentUsage(answer) {
  if (!answer || typeof answer !== 'object' || !answer.aggregates || !Array.isArray(answer.sessions)) {
    throw new Unread('OpenClaw answered sessions.usage without its aggregates');
  }
  // A time budget the gateway ran out of, or chats it is still summarizing:
  // every count is then at least what is shown.
  const partial = answer.partial != null;
  const byModel = Array.isArray(answer.aggregates.byModel) ? answer.aggregates.byModel : [];
  const chats = new Map();
  for (const session of answer.sessions) {
    for (const m of Array.isArray(session?.usage?.modelUsage) ? session.usage.modelUsage : []) {
      const key = JSON.stringify([m?.provider ?? null, m?.model ?? null]);
      chats.set(key, (chats.get(key) ?? 0) + 1);
    }
  }
  const rows = byModel.filter(m => m && typeof m === 'object').map(m => {
    const calls = count(m.count);
    const entry = {
      model: text(m.model),
      model_provider: text(m.provider),
      chats: chats.get(JSON.stringify([m.provider ?? null, m.model ?? null])) ?? 0,
      calls,
      tokens: tokens(m.totals),
      cost: cost(m.totals, calls),
    };
    if (partial) entry.incomplete = [...KEPT];
    return entry;
  }).sort((a, b) => total(b.tokens) - total(a.tokens));
  const models = rows.length > MAX_MODELS ? [...rows.slice(0, MAX_MODELS - 1), folded(rows.slice(MAX_MODELS - 1))] : rows;
  const top = answer.sessions.filter(s => s && typeof s === 'object' && s.usage).map(s => ({
    chat: text(s.sessionId ?? s.key),
    source: text(s.channel ?? s.origin?.provider),
    title: text(s.label),
    started_at: amount(s.usage.firstActivity) == null ? null : s.usage.firstActivity / 1000,
    model: text(s.model),
    calls: count(s.usage.messageCounts?.assistant),
    tokens: tokens(s.usage),
  })).sort((a, b) => total(b.tokens) - total(a.tokens)).slice(0, TOP_CHATS);
  return { found: true, models, top };
}

/** The models past the 49th in one row, so an agent's totals stay whole. */
function folded(rows) {
  const sum = field => rows.some(r => r.tokens[field] == null) ? null : rows.reduce((s, r) => s + r.tokens[field], 0);
  const usd = rows.every(r => r.cost.usd == null) ? null : rows.reduce((s, r) => s + (r.cost.usd ?? 0), 0);
  const kinds = new Set(rows.map(r => r.cost.kind));
  const entry = {
    model: `${rows.length} other models`,
    model_provider: null,
    chats: rows.reduce((s, r) => s + r.chats, 0),
    calls: rows.some(r => r.calls == null) ? null : rows.reduce((s, r) => s + r.calls, 0),
    tokens: { input: sum('input'), output: sum('output'), cache_read: sum('cache_read'), cache_write: sum('cache_write'), reasoning: null },
    cost: { usd, kind: kinds.size === 1 ? [...kinds][0] : 'mixed' },
  };
  const incomplete = [...new Set(rows.flatMap(r => r.incomplete ?? []))];
  if (incomplete.length) entry.incomplete = incomplete;
  return entry;
}

/** The gateway's address and credential, from OpenClaw's own settings. */
async function connection({ readConfig, resolveSecret, env }) {
  const port = Number(env.OPENCLAW_GATEWAY_PORT);
  if (!/^\d+$/u.test(env.OPENCLAW_GATEWAY_PORT ?? '') || port < 43000 || port > 43999) {
    throw new Unread('OpenClaw\'s gateway port is unknown: this sandbox has no enclos proxy port');
  }
  let snapshot;
  try { ({ snapshot } = await readConfig()); } catch { throw new Unread('OpenClaw could not read its settings'); }
  if (!snapshot?.valid || !snapshot.sourceConfig) throw new Unread('OpenClaw\'s settings are not valid; run OpenClaw doctor');
  const config = snapshot.sourceConfig, auth = config.gateway?.auth;
  if (config.gateway?.mode === 'remote') throw new Unread('OpenClaw\'s gateway is remote, not this sandbox\'s');
  if (!auth || !['token', 'password'].includes(auth.mode)) {
    throw new Unread('OpenClaw\'s gateway needs token or password authentication (gateway.auth.mode) for enclos to read its usage');
  }
  const field = auth.mode === 'password' ? 'password' : 'token';
  let resolved;
  try { resolved = await resolveSecret({ config, env, value: auth[field], path: `gateway.auth.${field}` }); }
  catch { resolved = undefined; }
  if (typeof resolved?.value !== 'string' || !resolved.value.trim() || resolved.unresolvedRefReason) {
    throw new Unread('OpenClaw could not resolve its gateway secret');
  }
  return { [field]: resolved.value, port: String(port), expectUrl: `ws://127.0.0.1:${port}`, json: true, timeout: '60000' };
}

/** The report for `agents` since `since` (Unix seconds), read through `sdk`. */
export async function report({ since, agents, readConfig, resolveSecret, callGateway, env = process.env, now = Date.now() }) {
  let options;
  try { options = await connection({ readConfig, resolveSecret, env }); }
  catch (error) {
    if (error instanceof Unread) return { format: FORMAT, agents: [], error: text(error.message) };
    throw error;
  }
  try { await callGateway('health', options, {}); }
  catch {
    return { format: FORMAT, agents: [], error: 'OpenClaw\'s gateway did not answer: start the sandbox and wait until it is ready' };
  }
  const window = { startDate: day(since), endDate: day(now / 1000), mode: 'utc' };
  const read = [];
  for (const agent of agents) {
    let entry;
    try {
      const answer = await callGateway('sessions.usage', options, { agentId: agent, ...window, limit: LISTED_CHATS });
      entry = agentUsage(answer);
    } catch (error) {
      // A gateway's own error names its code; its message may hold details
      // of the gateway's settings, so only the code is said.
      const code = typeof error?.gatewayCode === 'string' ? `: ${error.gatewayCode}` : '';
      entry = { error: error instanceof Unread ? text(error.message) : text(`sessions.usage failed${code}`) };
    }
    read.push({ ...entry, agent });
  }
  return { format: FORMAT, agents: read };
}

export async function nativeSdk() {
  // OpenClaw's rootless installer keeps its private Node in tools/node, with
  // OpenClaw beside it: its own package exports, never a cwd or NODE_PATH one.
  const nodeRoot = path.dirname(path.dirname(fs.realpathSync(process.execPath)));
  const packageFile = path.join(nodeRoot, 'lib/node_modules/openclaw/package.json');
  let version;
  try { ({ version } = JSON.parse(fs.readFileSync(packageFile))); }
  catch { throw new Unread('OpenClaw is not installed beside the Node that runs it'); }
  const parts = typeof version === 'string' && /^v?(\d+\.\d+\.\d+)([+-].+)?$/u.exec(version);
  const order = parts ? parts[1].localeCompare(MINIMUM, 'en', { numeric: true }) : -1;
  if (order < 0 || (order === 0 && parts[2]?.startsWith('-'))) throw new Unread(`OpenClaw ${MINIMUM} or newer reports usage to enclos`);
  const require = createRequire(packageFile);
  const method = async (subpath, name) => {
    let api;
    try { api = await import(pathToFileURL(require.resolve(`openclaw/plugin-sdk/${subpath}`))); }
    catch { throw new Unread(`OpenClaw has no plugin-sdk/${subpath}`); }
    if (typeof api?.[name] !== 'function') throw new Unread(`OpenClaw's plugin-sdk/${subpath} has no ${name}`);
    return api[name];
  };
  const [readConfig, resolveSecret, callGateway] = await Promise.all([
    method('config-mutation', 'readConfigFileSnapshotForWrite'),
    method('secret-input-runtime', 'resolveConfiguredSecretInputString'),
    method('gateway-runtime', 'callGatewayFromCli'),
  ]);
  return { readConfig, resolveSecret, callGateway };
}

export function write(out, value) {
  // Created here, never replaced: enclos checks that it reads a plain file.
  const fd = fs.openSync(out, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeSync(fd, JSON.stringify(value)); } finally { fs.closeSync(fd); }
}

export async function main(argv) {
  const [out, start, ...agents] = argv;
  try {
    const since = Number(start);
    if (!Number.isFinite(since)) throw new Unread('the window\'s start is not a time');
    write(out, await report({ since, agents, ...(await nativeSdk()) }));
  } catch (error) {
    // Said in the report, which enclos shows escaped, never on a terminal.
    const why = error instanceof Unread ? error.message : `${error?.name ?? 'Error'}: ${error?.message ?? error}`;
    write(out, { format: FORMAT, agents: [], error: text(why) });
  }
}

// Run by the adapter's command (`node -e`, which sets this), not when a test
// imports it.
if (process.env.ENCLOS_OPENCLAW_USAGE === '1') await main(process.argv.slice(1));
