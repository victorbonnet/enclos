import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import type { PluginRuntime } from 'openclaw/plugin-sdk/channel-core';
import { listNativeCommandSpecsForConfig } from 'openclaw/plugin-sdk/native-command-registry';
import { loadWebMediaRaw } from 'openclaw/plugin-sdk/web-media';
import { getAgentScopedMediaLocalRoots } from 'openclaw/plugin-sdk/media-local-roots';
import { renderPresentationForDelivery } from 'openclaw/plugin-sdk/interactive-runtime';
import { createChannel } from './channel.js';

const channel = createChannel({ commands: listNativeCommandSpecsForConfig, loadMedia: loadWebMediaRaw, mediaRoots: getAgentScopedMediaLocalRoots,
  renderPayload: payload => renderPresentationForDelivery({}, payload) });
export default defineChannelPluginEntry({
  id: 'enclos',
  name: 'enclos app',
  description: 'The enclos mobile app channel, reached through its host bridge.',
  plugin: channel.plugin,
  setRuntime(runtime: PluginRuntime) { channel.setRuntime(runtime); },
  registerFull: channel.registerFull,
});
