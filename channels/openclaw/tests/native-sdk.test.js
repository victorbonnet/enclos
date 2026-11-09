import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { createChannel, sessionPeer, TESTED_OPENCLAW } from '../channel.js';

const installed = process.env.ENCLOS_OPENCLAW_PACKAGE;
test('the installed public SDK registers the package and builds isolated session keys', { skip: !installed }, async () => {
  assert.equal(JSON.parse(readFileSync(path.join(installed, 'package.json'))).version, TESTED_OPENCLAW);
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/channel-core.js')));
  const routing = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/routing.js')));
  const channel = createChannel();
  const entry = sdk.defineChannelPluginEntry({ id: 'enclos', name: 'enclos app', description: 'enclos',
    plugin: channel.plugin, setRuntime: channel.setRuntime });
  let registered;
  entry.register({ registrationMode: 'full', runtime: { version: TESTED_OPENCLAW }, registerChannel(value) { registered = value.plugin; } });
  assert.equal(registered.id, 'enclos');
  const route = conversation => routing.buildAgentSessionKey({ agentId: 'main', channel: 'enclos', accountId: 'main',
    peer: { kind: 'direct', id: sessionPeer(conversation, 'alice') }, dmScope: 'per-account-channel-peer' });
  assert.notEqual(route('one'), route('two')); assert.equal(route('one'), route('one'));
  assert.ok(route('one').startsWith('agent:main:enclos:main:direct:'));
  const bound = routing.resolveAgentRoute({ cfg: { agents: { ownership: 'explicit', entries: { main: {} } },
    bindings: [{ agentId: 'main', match: { channel: 'enclos', accountId: 'main' } }] },
    channel: 'enclos', accountId: 'main', peer: { kind: 'direct', id: 'one' }, dmScope: 'per-account-channel-peer' });
  assert.equal(bound.agentId, 'main'); assert.equal(bound.matchedBy, 'binding.account');
});
