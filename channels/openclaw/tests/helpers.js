import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { once } from 'node:events';
import { message, encode } from '../protocol.js';

export function accountFixture(t, id = 'main') {
  const folder = mkdtempSync('/private/tmp/enclos-channel-');
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const tokenFile = path.join(folder, `${id}.env`);
  writeFileSync(tokenFile, JSON.stringify({ MOBILE_APP_TOKEN: 'only-for-tests' }), { mode: 0o600 });
  return { accountId: id, agentId: id, socket: path.join(folder, 'c.sock'),
    stateDir: path.join(folder, 'state'), tokenFile, home: `home.lab.${id}`, enabled: true };
}

export async function waitFor(check) {
  const deadline = Date.now() + 3000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error('condition did not become true');
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

export async function bridge(socket) {
  const peer = net.createConnection(socket);
  const pending = [];
  let buffer = '';
  peer.on('data', bytes => {
    buffer += bytes.toString('utf8');
    let newline;
    while ((newline = buffer.indexOf('\n')) >= 0) {
      pending.push(JSON.parse(buffer.slice(0, newline))); buffer = buffer.slice(newline + 1);
    }
  });
  peer.on('error', () => {});
  await once(peer, 'connect');
  return {
    peer, pending,
    send(value) { peer.write(encode(value)); },
    async next(type, of) {
      await waitFor(() => pending.some(p => p.type === type && (of == null || p.of === of)));
      return pending.splice(pending.findIndex(p => p.type === type && (of == null || p.of === of)), 1)[0];
    },
    async hello(fields = {}) {
      this.send(message('hello', { token: 'only-for-tests', ...fields }));
      return this.next('hello');
    },
    async close() { if (!peer.destroyed) { peer.destroy(); await once(peer, 'close'); } },
  };
}
