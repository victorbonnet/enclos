// Private native transfer bridge. Only public APIs of the pinned runtime are
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

async function main() {
  const [operation, agent, file, agentDir] = process.argv.slice(1);
  if (!/^[a-z][a-z0-9-]{1,40}$/.test(agent ?? '')) throw new Error('invalid agent');
  const nodeRoot = path.dirname(path.dirname(fs.realpathSync(process.execPath)));
  const packageFile = path.join(nodeRoot, 'lib/node_modules/openclaw/package.json');
  if (JSON.parse(fs.readFileSync(packageFile)).version !== '2026.11.3') throw new Error('native transfer needs the matching runtime');
  const require = createRequire(packageFile);
  const sdk = name => import(pathToFileURL(require.resolve(`openclaw/plugin-sdk/${name}`)));
  const stateDir = path.join(process.env.HOME, '.openclaw');
  const configFile = path.join(stateDir, 'openclaw.json');
  const signature = () => createHash('sha256').update(fs.readFileSync(configFile)).digest('hex');
  const initial = signature(); let live = true;
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { live = false; });
  const assertCurrent = () => { if (!live || signature() !== initial) throw new Error('native transfer authority changed'); };
  const [{ loadAuthProfileStoreWithoutExternalProfilesAsync }, auth, config, state, secrets] = await Promise.all([
    sdk('agent-runtime'), sdk('provider-auth'), sdk('config-mutation'), sdk('plugin-state-store-runtime'), sdk('secret-input-runtime'),
  ]);
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
    const shared = await loadAuthProfileStoreWithoutExternalProfilesAsync(undefined);
    const own = await loadAuthProfileStoreWithoutExternalProfilesAsync(agentDir, { inheritedAuthDir: agentDir });
    const bindings = [];
    for (const entry of await store.entries()) {
      if (bindingForAgent(entry.key, agent)) { assertIdleBinding(entry.value); bindings.push([entry.key, entry.value]); }
      else if (entry.key.startsWith('conversation:')) throw new Error('native conversation-bound Codex state needs a supported ownership export');
    }
    const resolve = async (value, location) => {
      if (value && typeof value === 'object' && ['env', 'file', 'exec'].includes(value.source) && typeof value.provider === 'string' && typeof value.id === 'string') {
        const resolved = await secrets.resolveConfiguredSecretInputString({ config: snapshot.sourceConfig, env: process.env, value, path: location });
        if (typeof resolved.value !== 'string' || resolved.unresolvedRefReason) throw new Error('source credential could not be resolved');
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
    for (const key of ['agents', 'tools', 'skills', 'models', 'messages', 'commands', 'session', 'plugins', 'auth']) {
      if (sourceConfig[key] != null) sourceConfig[key] = await resolve(sourceConfig[key], key);
    }
    assertCurrent();
    fs.writeFileSync(file, JSON.stringify({ config: sourceConfig, agentNames, sharedAuth: await materializeAuth(shared), localAuth: await materializeAuth(own), bindings }), { mode: 0o600, flag: 'wx' });
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
