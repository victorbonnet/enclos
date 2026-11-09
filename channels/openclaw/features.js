import path from 'node:path';
import { checkedId, message } from './protocol.js';

const line = (text, maximum) => [...String(text).replace(/[\x00-\x1f\x7f-\x9f]/gu, ' ').replace(/\s+/gu, ' ').trim()].slice(0, maximum).join('');

export function commandCatalog(native, cfg) {
  const rows = [], seen = new Set();
  for (const command of native(cfg, { provider: 'enclos', includeBundledChannelFallback: false })) {
    const name = command.name?.toLowerCase();
    if (!/^[a-z0-9_-]{1,32}$/u.test(name ?? '') || seen.has(name) || ['sethome', 'set-home', 'start', 'topic'].includes(name)) continue;
    const description = line(command.description ?? '', 120);
    const args = command.args?.map(arg => arg.required ? `<${arg.name}>` : `[${arg.name}]`).join(' ') ?? (command.acceptsArgs ? '[arguments]' : '');
    const row = { name, description, ...(args ? { args: line(args, 60) } : {}) };
    if (Buffer.byteLength(JSON.stringify([...rows, row])) > 44000) break;
    rows.push(row); seen.add(name);
  }
  return rows;
}

export function registerFeatures(api, { findTurn, assertTurn, running }) {
  if (typeof api.on !== 'function') return { tools: false, policy: false };
  const observe = (phase, event, ctx) => {
    const turn = findTurn(ctx);
    if (!turn) return;
    try {
      assertTurn(turn);
      const call = checkedId(event.toolCallId ?? ctx.toolCallId, 'tool call');
      const name = checkedId(event.toolName ?? ctx.toolName, 'tool name');
      const fields = { conversation: turn.conversation, call, name, phase };
      if (phase === 'start') fields.label = line(name, 120);
      else {
        fields.ok = !event.error && event.result?.isError !== true;
        if (Number.isFinite(event.durationMs) && event.durationMs >= 0) fields.duration_ms = Math.floor(event.durationMs);
      }
      turn.active.transport.write(message('tool', fields));
      if (phase === 'end' && policy) {
        const failure = event.error ?? (event.result?.isError ? event.result.content?.filter(c => c.type === 'text').slice(0, 4).map(c => String(c.text).slice(0, 4096)).join('\n') : undefined);
        const kind = ({ read: 'read', write: 'write', edit: 'write' })[name];
        const target = event.params?.path ?? event.params?.file_path;
        if (kind && typeof target === 'string' && path.isAbsolute(target) && Buffer.byteLength(target) <= 4096 &&
            !/[\x00-\x1f\x7f-\x9f]/u.test(target) && /EACCES|EPERM|permission denied|operation not permitted/iu.test(failure ?? '')) {
          turn.active.transport.enqueue(message('approval.request', { conversation: turn.conversation,
            access: { kind, target, private: false }, action: line(`${kind === 'read' ? 'Read' : 'Write'} ${target}`, 200) }));
        }
      }
    } catch { /* Observing a tool never changes its native guard/result. */ }
  };
  api.on('before_tool_call', (event, ctx) => { observe('start', event, ctx); });
  api.on('after_tool_call', (event, ctx) => { observe('end', event, ctx); });
  const policy = typeof api.registerTool === 'function';
  if (policy) {
    api.on('before_prompt_build', (_event, ctx) => {
      const turn = findTurn(ctx);
      if (!turn) return;
      assertTurn(turn);
      const text = turn.active.transport.state.policyContext;
      if (text) return { prependContext: text };
    });
    api.registerTool({ contextVersion: 2, create(ctx) {
      const turn = findTurn(ctx);
      if (!turn || typeof ctx.assertInvocationCurrent !== 'function') return null;
      return {
        name: 'enclos_request_access',
        label: 'Request sandbox access',
        description: 'Ask the host\'s person for a sandbox policy scope. This requests access; it grants nothing. Wait for the person and updated policy context before trying again.',
        parameters: { type: 'object', additionalProperties: false, required: ['kind', 'target', 'action'], properties: {
          kind: { type: 'string', enum: ['network', 'read', 'write'] },
          target: { type: 'string', minLength: 1, maxLength: 4096 },
          action: { type: 'string', minLength: 1, maxLength: 200 },
          private: { type: 'boolean' },
        } },
        async execute(_id, params) {
          ctx.assertInvocationCurrent(); assertTurn(turn);
          if (!['network', 'read', 'write'].includes(params.kind) || typeof params.target !== 'string' || !params.target ||
              Buffer.byteLength(params.target) > 4096 || /[\x00-\x1f\x7f-\x9f]/u.test(params.target) ||
              (params.kind !== 'network' && !path.isAbsolute(params.target)) || typeof params.action !== 'string' ||
              !params.action.trim() || Buffer.byteLength(params.action) > 200 || /[\x00-\x1f\x7f-\x9f]/u.test(params.action) ||
              (params.private != null && typeof params.private !== 'boolean')) throw new Error('request one explicit valid sandbox scope');
          const request = message('approval.request', { conversation: turn.conversation,
            access: { kind: params.kind, target: params.target, private: params.private === true }, action: params.action });
          turn.active.transport.enqueue(request);
          return { content: [{ type: 'text', text: 'The sandbox access request was sent. It grants no access until the host\'s person approves it. Wait for updated policy context before trying again.' }],
            details: { request: request.id, status: 'requested' } };
        },
      };
    } }, { name: 'enclos_request_access', workspaceAccess: false });
  }
  return { tools: true, policy };
}
