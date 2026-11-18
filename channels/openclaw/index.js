import { defineChannelPluginEntry } from 'openclaw/plugin-sdk/channel-core';

import { listNativeCommandSpecsForConfig } from 'openclaw/plugin-sdk/native-command-registry';
import { loadWebMediaRaw } from 'openclaw/plugin-sdk/web-media';
import { getAgentScopedMediaLocalRoots } from 'openclaw/plugin-sdk/media-local-roots';
import { renderPresentationForDelivery } from 'openclaw/plugin-sdk/interactive-runtime';
import { createChannelApprovalCapability } from 'openclaw/plugin-sdk/approval-delivery-runtime';
import { createChannelApprovalNativeRuntimeAdapterAsync, CHANNEL_APPROVAL_NATIVE_RUNTIME_CONTEXT_CAPABILITY } from 'openclaw/plugin-sdk/approval-handler-runtime';
import { resolveApprovalOverGateway } from 'openclaw/plugin-sdk/approval-gateway-runtime';
import { registerChannelRuntimeContext } from 'openclaw/plugin-sdk/channel-runtime-context';
import { createChannel } from './channel.js';
import { createNativeApprovals } from './native-approvals.js';

const nativeApprovals = createNativeApprovals({ createChannelApprovalCapability, createChannelApprovalNativeRuntimeAdapterAsync,
  CHANNEL_APPROVAL_NATIVE_RUNTIME_CONTEXT_CAPABILITY, resolveApprovalOverGateway, registerChannelRuntimeContext });
const channel = createChannel({ commands: listNativeCommandSpecsForConfig, loadMedia: loadWebMediaRaw, mediaRoots: getAgentScopedMediaLocalRoots,
  renderPayload: payload => renderPresentationForDelivery({}, payload), nativeApprovals });
export default defineChannelPluginEntry({
  id: 'enclos',
  name: 'enclos app',
  description: 'The enclos mobile app channel, reached through its host bridge.',
  plugin: channel.plugin,
  setRuntime(runtime               ) { channel.setRuntime(runtime); },
  registerFull: channel.registerFull,
});
