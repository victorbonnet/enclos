// Each ingress owns its native public replyOptions.abortSignal. Never select a
// running operation from a conversation/session lookup when stopping a turn.
import { checkedId } from './protocol.js';

export function createNativeTurns(assertCurrent) {
  const active = new Map();
  let closed = false;
  return {
    begin(incoming) {
      assertCurrent();
      if (closed || active.has(incoming.id)) throw new Error('native ingress is not available');
      const owner = { conversation: incoming.conversation, controller: new AbortController() };
      active.set(incoming.id, owner);
      return { signal: owner.controller.signal,
        finish() { if (active.get(incoming.id) === owner) active.delete(incoming.id); },
      };
    },
    handleControl(control) {
      if (control.type !== 'turn.abort') return false;
      checkedId(control.conversation, 'conversation'); checkedId(control.of, 'of');
      assertCurrent();
      const owner = active.get(control.of);
      if (!closed && owner?.conversation === control.conversation) owner.controller.abort();
      // Completed, repeated and unknown targets have no effect. Acknowledging
      // the request does not claim that native cleanup has drained.
      return true;
    },
    close() { closed = true; for (const owner of active.values()) owner.controller.abort(); active.clear(); },
  };
}
