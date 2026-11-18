// A transient view of the enclos ingresses currently owned by native dispatch.
// It is not the Gateway's complete run, scheduler or task inventory.
import { message } from './protocol.js';

export function createActivity(transport, assertCurrent) {
  const active = new Map();
  let closed = false;
  let snapshot = { doing: [], since: 0 };
  function publish() {
    if (closed || !transport.bridgeCapabilities?.has('activity')) return;
    try {
      assertCurrent();
      transport.write(message('agent.activity', snapshot));
    } catch { /* Reporting cannot fail the native dispatch or revive an account. */ }
  }
  function update() {
    const conversations = [...new Set(active.values())].sort().slice(0, 16);
    const doing = conversations.map(conversation => ({ kind: 'answering', conversation }));
    if (JSON.stringify(doing) === JSON.stringify(snapshot.doing)) return;
    snapshot = { doing, since: doing.length ? Math.floor(Date.now() / 1000) : 0 };
    publish();
  }
  return {
    capabilities: () => ['activity'],
    onHello: publish,
    begin(incoming) {
      if (closed) return () => {};
      active.set(incoming.id, incoming.conversation);
      update();
      return () => {
        if (!closed && active.delete(incoming.id)) update();
      };
    },
    close() { closed = true; active.clear(); snapshot = { doing: [], since: 0 }; },
  };
}
