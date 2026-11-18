// Private native transfer bridge. Only public APIs of a supported runtime are
// imported; credentials and opaque bindings stay in private data files.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

export function mergeAuth(store, inherited, own) {
  store.profiles = { ...(inherited?.profiles ?? {}), ...store.profiles, ...(own?.profiles ?? {}) };
  for (const key of ['order', 'lastGood']) store[key] = { ...(inherited?.[key] ?? {}), ...(store[key] ?? {}), ...(own?.[key] ?? {}) };
  return true;
}

export function bindingForAgent(key, agent) {
  return key.startsWith(`session-key:${agent}:`) || key.startsWith(`session:${agent}:`);
}

export function assertIdleBinding(value, now = Date.now()) {
  if (!value || typeof value !== 'object') throw new Error('invalid native binding');
  if (value.binding?.connectionScope === 'supervision' || value.binding?.supervisionSourceThreadId) throw new Error('supervised Codex state needs a supported native export');
  if (value.lease && (!Number.isFinite(value.lease.expiresAt) || value.lease.expiresAt > now)) throw new Error('native Codex binding is leased; finish its turn before exporting');
  if (value.binding?.pendingSupervisionBranch || value.nativeSubagentAssignments?.assignments?.length ||
      value.nativeSubagentSubmissions?.receipts?.length || value.nativeSubagentTaskImport) {
    throw new Error('native Codex binding has unresolved work; finish or stop it before exporting');
  }
}

export function legacyThreadOwner(key, value, catalog) {
  if (!key.startsWith('conversation:') || value?.version !== 1 || value.state !== 'active' ||
      Object.keys(value).some(k => !['version', 'state', 'binding'].includes(k))) throw new Error('unsupported orphan native binding');
  assertIdleBinding(value);
  const owners = catalog.get(value.binding?.threadId) ?? [];
  if (owners.length !== 1) throw new Error('orphan Codex thread has ambiguous or missing physical provenance');
  return owners[0];
}

async function legacyThreadCatalog(config, resolveAgentDir) {
  const { DatabaseSync } = await import('node:sqlite');
  const home = fs.realpathSync(process.env.HOME);
  const inside = (root, file) => file.startsWith(root + path.sep);
  const global = new DatabaseSync(path.join(home, '.openclaw/state/openclaw.sqlite'), { readOnly: true });
  try {
    if (global.prepare('select count(*) as n from current_conversation_bindings').get().n !== 0) {
      throw new Error('registered native conversation bindings need a supported ownership export');
    }
  } finally { global.close(); }
  const result = new Map();
  for (const agent of Object.keys(config.agents?.entries ?? {})) {
    const agentDir = fs.realpathSync(resolveAgentDir(config, agent));
    if (!inside(home, agentDir)) throw new Error('native thread home is outside its sandbox');
    const codexHome = path.join(agentDir, 'codex-home');
    const file = path.join(codexHome, 'state_5.sqlite');
    if (!fs.existsSync(file)) continue;
    if (!inside(agentDir, fs.realpathSync(file))) throw new Error('linked native thread catalog leaves its agent');
    const db = new DatabaseSync(file, { readOnly: true });
    try {
      for (const row of db.prepare('select id,rollout_path from threads').all()) {
        // Older copied catalogs can retain pre-Enclos absolute paths. Keep
        // those records as reference data, never as active native bindings.
        const marker = '/codex-home/';
        const index = row.rollout_path.lastIndexOf(marker);
        if (index < 0) throw new Error('native rollout has no captured agent-home provenance');
        const relative = row.rollout_path.slice(index + marker.length);
        const captured = fs.realpathSync(path.join(codexHome, relative));
        if (!inside(fs.realpathSync(codexHome), captured) || !fs.statSync(captured).isFile()) throw new Error('native rollout bytes are not captured in its agent');
        const owners = result.get(row.id) ?? [];
        owners.push({ agent, rollout: path.relative(agentDir, captured) }); result.set(row.id, owners);
      }
    } finally { db.close(); }
  }
  return result;
}

async function main() {
  const [operation, agent, file, agentDir, credentialFiles = '{}'] = process.argv.slice(1);
  if (!/^[a-z][a-z0-9-]{1,40}$/.test(agent ?? '')) throw new Error('invalid agent');
  const nodeRoot = path.dirname(path.dirname(fs.realpathSync(process.execPath)));
  const packageFile = path.join(nodeRoot, 'lib/node_modules/openclaw/package.json');
  const { version } = JSON.parse(fs.readFileSync(packageFile));
  const release = typeof version === 'string' && /^(\d+\.\d+\.\d+)([+-].+)?$/u.exec(version);
  const order = release ? release[1].localeCompare('2026.11.5', 'en', { numeric: true }) : -1;
  if (order < 0 || (order === 0 && release[2]?.startsWith('-'))) throw new Error('Update OpenClaw to 2026.11.5 or newer before transferring agent data.');
  const require = createRequire(packageFile);
  const sdk = name => import(pathToFileURL(require.resolve(`openclaw/plugin-sdk/${name}`)));
  const contracts = {
    'agent-runtime': ['loadAuthProfileStoreWithoutExternalProfilesAsync', 'resolveAgentDir'],
    'provider-auth': ['updateAuthProfileStoreWithLock'],
    'config-mutation': ['readConfigFileSnapshotForWrite'],
    'plugin-state-store-runtime': ['createPluginStateKeyedStoreV2'],
    'secret-input-runtime': ['resolveConfiguredSecretInputString'],
  };
  const [{ loadAuthProfileStoreWithoutExternalProfilesAsync, resolveAgentDir }, auth, config, state, secrets] = await Promise.all(
    Object.entries(contracts).map(async ([name, methods]) => {
      let module;
      try { module = await sdk(name); }
      catch { throw new Error(`OpenClaw could not load plugin-sdk/${name}. Update OpenClaw or enclos.`); }
      for (const method of methods) if (typeof module[method] !== 'function') {
        throw new Error(`OpenClaw plugin-sdk/${name} is missing ${method}. Update OpenClaw or enclos.`);
      }
      return module;
    }),
  );
  if (operation === 'check') {
    fs.writeFileSync(file, JSON.stringify(version), { mode: 0o600, flag: 'wx' });
    return;
  }
  const stateDir = path.join(process.env.HOME, '.openclaw');
  const configFile = path.join(stateDir, 'openclaw.json');
  const signature = () => createHash('sha256').update(fs.readFileSync(configFile)).digest('hex');
  const initial = signature(); let live = true;
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { live = false; });
  const assertCurrent = () => { if (!live || signature() !== initial) throw new Error('native transfer authority changed'); };
  const store = state.createPluginStateKeyedStoreV2('codex', {
    namespace: 'app-server-thread-bindings', maxEntries: 50000, overflowPolicy: 'reject-new', env: process.env,
  }, { assertCurrent });
  if (operation === 'prepare') {
    // Before restoring main's database, let the native lifecycle establish
    // a fresh shared store. Otherwise its legacy-main fallback treats the
    // restored main-local profiles as shared credentials for other agents.
    const prepared = await auth.updateAuthProfileStoreWithLock({ stateDir, sharedStoreWrite: true,
      saveOptions: { filterExternalAuthProfiles: false, syncExternalCli: false }, updater: () => false });
    if (!prepared) throw new Error('native shared credential preparation was not confirmed');
  } else if (operation === 'export') {
    const { snapshot } = await config.readConfigFileSnapshotForWrite();
    if (!snapshot?.valid || !snapshot.sourceConfig) throw new Error('native config is invalid');
    const resolutionConfig = structuredClone(snapshot.sourceConfig);
    const aliases = JSON.parse(credentialFiles);
    for (const provider of Object.values(resolutionConfig.secrets?.providers ?? {})) {
      if (provider.source === 'file' && Object.hasOwn(aliases, provider.path)) provider.path = aliases[provider.path];
    }
    const shared = await loadAuthProfileStoreWithoutExternalProfilesAsync(undefined);
    const own = await loadAuthProfileStoreWithoutExternalProfilesAsync(agentDir, { inheritedAuthDir: agentDir });
    const bindings = [], legacyBindings = [];
    const entries = await store.entries();
    const catalog = entries.some(e => e.key.startsWith('conversation:')) ? await legacyThreadCatalog(snapshot.sourceConfig, resolveAgentDir) : null;
    for (const entry of entries) {
      if (bindingForAgent(entry.key, agent)) { assertIdleBinding(entry.value); bindings.push([entry.key, entry.value]); }
      else if (entry.key.startsWith('conversation:')) {
        const owner = legacyThreadOwner(entry.key, entry.value, catalog);
        if (owner.agent === agent) legacyBindings.push({ key: entry.key, value: entry.value, rollout: owner.rollout });
      }
    }
    const resolve = async (value, location) => {
      if (value && typeof value === 'object' && ['env', 'file', 'exec', 'store'].includes(value.source) && typeof value.provider === 'string' && typeof value.id === 'string') {
        if (value.source === 'file' && /^(?:enclos-sandbox|enclos-[0-9a-f]{16})$/u.test(value.provider)) return value;
        const resolved = await secrets.resolveConfiguredSecretInputString({ config: resolutionConfig, env: process.env, value, path: location });
        if (typeof resolved.value !== 'string' || resolved.unresolvedRefReason) throw new Error(`source credential could not be resolved at ${location}`);
        return resolved.value;
      }
      if (Array.isArray(value)) return Promise.all(value.map((v, i) => resolve(v, `${location}.${i}`)));
      if (value && typeof value === 'object') {
        const result = {};
        for (const [key, nested] of Object.entries(value)) result[key] = await resolve(nested, `${location}.${key}`);
        return result;
      }
      return value;
    };
    const materializeAuth = async input => {
      const result = await resolve(input, 'auth');
      for (const credential of Object.values(result?.profiles ?? {})) for (const field of ['key', 'token', 'access', 'refresh']) {
        if (typeof credential[`${field}Ref`] === 'string') { credential[field] = credential[`${field}Ref`]; delete credential[`${field}Ref`]; }
      }
      return result;
    };
    const sourceConfig = structuredClone(snapshot.sourceConfig);
    const agentNames = Object.keys(sourceConfig.agents?.entries ?? {});
    if (sourceConfig.agents?.entries) sourceConfig.agents.entries = { [agent]: sourceConfig.agents.entries[agent] };
    // Keep native settings references intact. The enclos envelope carries
    // the granted values separately, and import rebinds the reference.
    assertCurrent();
    fs.writeFileSync(file, JSON.stringify({ version, config: sourceConfig, agentNames, sharedAuth: await materializeAuth(shared), localAuth: await materializeAuth(own), bindings, legacyBindings }), { mode: 0o600, flag: 'wx' });
  } else if (operation === 'import') {
    const input = JSON.parse(fs.readFileSync(file));
    for (const [key, value] of input.bindings) {
      if (!bindingForAgent(key, agent)) throw new Error('foreign native binding in agent data');
      assertIdleBinding(value);
      const existing = await store.lookup(key);
      if (existing != null && JSON.stringify(existing) !== JSON.stringify(value)) throw new Error('destination native binding already exists');
      if (existing == null) await store.registerIfAbsent(key, value);
      if (JSON.stringify(await store.lookup(key)) !== JSON.stringify(value)) throw new Error('native binding publication was not confirmed');
    }
    assertCurrent();
    const restored = await auth.updateAuthProfileStoreWithLock({ stateDir, agentDir, sharedStoreWrite: false,
      saveOptions: { filterExternalAuthProfiles: false, syncExternalCli: false },
      updater: target => mergeAuth(target, input.sharedAuth, input.localAuth) });
    if (!restored) throw new Error('native credential restore was not confirmed');
  } else throw new Error('unknown native transfer operation');
  live = false;
}

// This helper is embedded with `node -e`; importing it in tests does no I/O.
if (process.env.ENCLOS_OPENCLAW_TRANSFER === '1') {
  main().catch(error => {
    try { fs.writeFileSync(`${process.argv[3]}.error`, String(error.stack ?? error.name), { mode: 0o600, flag: 'wx' }); } catch {}
    console.error('OpenClaw native transfer failed; inspect the private transfer diagnostic.'); process.exitCode = 1;
  });
}
