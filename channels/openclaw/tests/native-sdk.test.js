import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { createChannel, sessionPeer, TESTED_OPENCLAW } from '../channel.js';
import { commandCatalog } from '../features.js';
import { stageMedia } from '../media.js';
import { accountFixture } from './helpers.js';

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
  const commands = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/native-command-registry.js')));
  const listed = commandCatalog(commands.listNativeCommandSpecsForConfig, {});
  assert.ok(listed.some(c => c.name === 'help'));
  assert.ok(listed.every(c => c.description.length <= 120 && /^[a-z0-9_-]{1,32}$/.test(c.name)));
});

test('the installed scoped media loader preserves HTML and rejects an unrelated local root', { skip: !installed }, async t => {
  const loader = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/web-media.js')));
  const roots = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/media-local-roots.js')));
  const account = accountFixture(t), workspace = path.dirname(account.socket), source = path.join(workspace, 'page.html');
  const html = '<!doctype html><p>Native SDK HTML fixture</p>';
  writeFileSync(source, html);
  const cfg = { agents: { ownership: 'explicit', entries: { main: { workspace } } } };
  const [attachment] = await stageMedia(account, [source], { cfg,
    sdk: { loadMedia: loader.loadWebMediaRaw, mediaRoots: roots.getAgentScopedMediaLocalRoots } });
  assert.equal(attachment.mime, 'text/html'); assert.equal(attachment.name, 'page.html');
  assert.equal(readFileSync(path.join(workspace, 'media', attachment.file), 'utf8'), html);
  const outside = mkdtempSync('/private/tmp/enclos-sdk-outside-'); t.after(() => rmSync(outside, { recursive: true, force: true }));
  const excluded = path.join(outside, 'outside.txt'); writeFileSync(excluded, 'fixture');
  await assert.rejects(loader.loadWebMediaRaw(excluded, { localRoots: [workspace] }));
});

test('the installed native fallback retains every question and respects existing fallback text', { skip: !installed }, async () => {
  const sdk = await import(pathToFileURL(path.join(installed, 'dist/plugin-sdk/interactive-runtime.js')));
  const id = `ask_${'a'.repeat(32)}`;
  const payload = { channelData: { askUser: { questionId: id } }, presentation: { title: 'Questions for you', blocks: [
    { type: 'text', text: 'First question?' },
    { type: 'buttons', buttons: [
      { label: 'First option', action: { type: 'question', questionId: id, optionValue: 'first' } },
      { label: 'Second option', action: { type: 'question', questionId: id, optionValue: 'second' } },
    ] },
    { type: 'context', text: 'Keep this complete explanation.' },
    { type: 'text', text: 'Second question?' },
    { type: 'select', placeholder: 'Choose several', options: [
      { label: 'Third option', value: 'third' }, { label: 'Fourth option', value: 'fourth' },
    ] },
  ] } };
  const rendered = await sdk.renderPresentationForDelivery({}, payload);
  assert.equal(rendered.presentation, undefined);
  assert.equal(rendered.text, 'Questions for you\n\nFirst question?\n\n- First option\n- Second option\n\nKeep this complete explanation.\n\nSecond question?\n\nChoose several:\n- Third option\n- Fourth option');
  assert.deepEqual(rendered.channelData, payload.channelData);
  assert.equal(rendered.text.includes(id), false);
  const fallback = 'Complete native text, including the native answer instructions.';
  assert.equal((await sdk.renderPresentationForDelivery({}, { ...payload, text: fallback, presentationTextMode: 'fallback' })).text, fallback);
  const credential = { text: 'Never send credentials in chat; open the trusted Control UI.', channelData: payload.channelData };
  assert.equal(await sdk.renderPresentationForDelivery({}, credential), credential);
});
