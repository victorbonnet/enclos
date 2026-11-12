// Public native session metadata; no native store paths or schemas are copied.
import { message, ProtocolError } from './protocol.js';

function displayTitle(entry) {
  const value = [entry?.label, entry?.displayName, entry?.autoLabel, entry?.subject]
    .find(value => typeof value === 'string' && value.trim());
  return value ? [...value.replace(/[\x00-\x1f\x7f-\x9f]/gu, ' ').replace(/\s+/gu, ' ').trim()].slice(0, 100).join('') : '';
}

export function createNativeTitles(runtime, account, transport, { currentConfig, assertCurrent, sessionKeyFor }) {
  const session = runtime?.agent?.session;
  const available = ['resolveStorePath', 'getSessionEntryAsync', 'prepareSessionEntryPatch'].every(key => typeof session?.[key] === 'function');
  if (!available) return { available: false, watch() {}, refresh() {}, close() {}, async handleControl() { return false; } };
  const storePath = session.resolveStorePath(currentConfig().session?.store, { agentId: account.agentId });
  const watched = new Map(), pending = new Map(), last = new Map();
  let closed = false;
  const assertOwner = () => {
    assertCurrent();
    if (closed || session.resolveStorePath(currentConfig().session?.store, { agentId: account.agentId }) !== storePath) throw new Error('native session owner was stopped or reconfigured');
  };
  function target(conversation) {
    assertOwner();
    const sessionKey = sessionKeyFor(conversation);
    if (!sessionKey) return undefined;
    return { agentId: account.agentId, sessionKey, storePath };
  }
  function watch(conversation) {
    const selected = target(conversation);
    if (selected) watched.set(selected.sessionKey, conversation);
    return selected;
  }
  async function read(conversation) {
    const selected = watch(conversation);
    if (!selected) return;
    const entry = await session.getSessionEntryAsync({ ...selected, readConsistency: 'latest' });
    assertOwner();
    if (sessionKeyFor(conversation) !== selected.sessionKey) return;
    const title = displayTitle(entry);
    if (!title || last.get(conversation) === title) return;
    transport.enqueue(message('conversation.title', { conversation, title }));
    last.set(conversation, title);
  }
  function refresh(conversation) {
    if (closed) return Promise.resolve();
    const existing = pending.get(conversation);
    if (existing) { existing.again = true; return existing.task; }
    // Observation must never change the result of the native turn.
    const item = { again: true };
    item.task = (async () => {
      while (!closed && item.again) {
        item.again = false;
        await read(conversation).catch(() => {});
      }
    })().finally(() => pending.delete(conversation));
    pending.set(conversation, item);
    return item.task;
  }
  for (const conversation of Object.keys(transport.state.routes)) watch(conversation);
  const unsubscribe = runtime.gateway?.subscribeSessionChanges?.(event => {
    const conversation = watched.get(event.sessionKey);
    if (conversation && (!event.agentId || event.agentId === account.agentId)) void refresh(conversation);
  });
  return {
    available: true, watch, refresh,
    async handleControl(control, assertControlCurrent = () => {}) {
      if (control.type !== 'conversation.rename') return false;
      if (typeof control.title !== 'string' || control.title.trim().length > 512 || /[\x00-\x1f\x7f-\x9f]/u.test(control.title)) throw new ProtocolError('bad_message', 'native title must be at most 512 characters of single-line text');
      const selected = watch(control.conversation);
      if (!selected) return true;
      const title = control.title.trim();
      const assertTarget = () => {
        assertControlCurrent();
        assertOwner();
        if (sessionKeyFor(control.conversation) !== selected.sessionKey) throw new Error('native conversation binding changed');
      };
      try {
        const updated = await session.prepareSessionEntryPatch({ ...selected, preserveActivity: true, requireWriteSuccess: true,
          authority: { kind: 'host', assertCurrent: assertTarget },
          prepare(entry, context) {
            assertTarget();
            // Renaming an unused conversation does not create a native session.
            // Display titles may repeat. Addressable native labels keep their
            // own validation/uniqueness contract and are never rewritten here.
            return context.existingEntry && entry.sessionId ? { displayName: title || undefined } : null;
          },
        });
        assertTarget();
        if (updated) { last.delete(control.conversation); await refresh(control.conversation); }
      } catch (error) {
        assertTarget();
        throw new ProtocolError('conflict', 'the native session kept its current title; refresh before renaming it again');
      }
      return true;
    },
    close() { closed = true; unsubscribe?.(); watched.clear(); },
  };
}
