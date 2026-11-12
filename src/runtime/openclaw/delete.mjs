// Owner-side native Gateway client. Tokens stay in this process's memory;
// nothing is written to config, added to argv, or exported to a child.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

class OwnerRefusal extends Error {}
const unavailable = () => new OwnerRefusal('OpenClaw agent deletion needs its authenticated local Gateway. Start this sandbox with `enclos sandbox start <sandbox>`, wait until it is ready, then retry. No deletion is retried automatically.');

export async function deleteAgent({ agentId, readConfig, resolveSecret, callGateway, env = process.env }) {
  if (!/^[a-z0-9_][a-z0-9_-]{0,63}$/u.test(agentId ?? '')) throw new Error('Invalid OpenClaw agent id.');
  const port = Number(env.OPENCLAW_GATEWAY_PORT);
  if (!/^\d+$/u.test(env.OPENCLAW_GATEWAY_PORT ?? '') || port < 43000 || port > 43999) throw unavailable();
  const { snapshot } = await readConfig();
  if (!snapshot?.valid || !snapshot.sourceConfig || snapshot.sourceConfig.gateway?.mode === 'remote') throw unavailable();
  const config = snapshot.sourceConfig, auth = config.gateway?.auth;
  if (!auth || !['token', 'password'].includes(auth.mode)) throw unavailable();
  const field = auth.mode === 'password' ? 'password' : 'token';
  const resolved = await resolveSecret({ config, env, value: auth[field], path: `gateway.auth.${field}` });
  if (typeof resolved.value !== 'string' || !resolved.value.trim() || resolved.unresolvedRefReason) throw unavailable();
  const options = { [field]: resolved.value, port: String(port), expectUrl: `ws://127.0.0.1:${port}`, json: true, timeout: '10000' };
  // A failed readiness/auth probe cannot dispatch a deletion. No fallback
  // edits native files, changes auth, or guesses whether a write succeeded.
  try { await callGateway('health', options, {}); }
  catch { throw unavailable(); }
  let result;
  try { result = await callGateway('agents.delete', options, { agentId, deleteFiles: true }); }
  catch { throw new OwnerRefusal('OpenClaw did not confirm agent deletion. Refresh its native agents before retrying; the request was not resent.'); }
  return { agentId, transport: 'gateway',
    ...(Array.isArray(result.removed) ? { removed: result.removed } : {}),
    ...(Array.isArray(result.failed) ? { failed: result.failed } : {}),
    ...(result.purgeFailed === true ? { purgeFailed: true } : {}) };
}

export async function nativeOwnerSdk() {
  // The official rootless installer maintains tools/node -> private Node.
  // Resolve its own package exports; cwd/NODE_PATH never select a host SDK.
  const nodeRoot = path.dirname(path.dirname(fs.realpathSync(process.execPath)));
  const packageFile = path.join(nodeRoot, 'lib/node_modules/openclaw/package.json');
  if (JSON.parse(fs.readFileSync(packageFile)).version !== '2026.11.2') throw new Error('OpenClaw owner helpers need the matching tested runtime version.');
  const require = createRequire(packageFile);
  const sdk = async subpath => import(pathToFileURL(require.resolve(`openclaw/plugin-sdk/${subpath}`)));
  const [{ readConfigFileSnapshotForWrite }, { resolveConfiguredSecretInputString }, { callGatewayFromCli }] = await Promise.all([
    sdk('config-mutation'), sdk('secret-input-runtime'), sdk('gateway-runtime'),
  ]);
  return { readConfig: readConfigFileSnapshotForWrite, resolveSecret: resolveConfiguredSecretInputString, callGateway: callGatewayFromCli };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const sdk = await nativeOwnerSdk();
    const result = await deleteAgent({ agentId: process.argv[2], ...sdk });
    console.log(JSON.stringify(result));
  } catch (error) {
    // Upstream exceptions can contain source details; never print resolved
    // credentials or a serialized config, even on a native client failure.
    console.error(error instanceof OwnerRefusal ? error.message : unavailable().message);
    process.exitCode = 1;
  }
}
