import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';

import { createChannel } from './channel.js';

const channel = createChannel();
export default defineChannelPluginEntry({
  id: 'enclos',
  name: 'enclos app',
  description: 'The enclos mobile app channel, reached through its host bridge.',
  plugin: channel.plugin,
  setRuntime(runtime               ) { channel.setRuntime(runtime); },
});
