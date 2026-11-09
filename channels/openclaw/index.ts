import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';
import type { PluginRuntime } from 'openclaw/plugin-sdk/channel-core';
import { listNativeCommandSpecsForConfig } from 'openclaw/plugin-sdk/native-command-registry';
import { createChannel } from './channel.js';

const channel = createChannel({ commands: listNativeCommandSpecsForConfig });
export default defineChannelPluginEntry({
  id: 'enclos',
  name: 'enclos app',
  description: 'The enclos mobile app channel, reached through its host bridge.',
  plugin: channel.plugin,
  setRuntime(runtime: PluginRuntime) { channel.setRuntime(runtime); },
  registerFull: channel.registerFull,
});
