// Authenticated Unix socket plus durable outbound messages. No OpenClaw imports.
import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { checkedId, decode, encode, message, MAX_MESSAGE_BYTES, ProtocolError, tokenMatches } from './protocol.js';

const MAX_STATE_BYTES = 16 * 1024 * 1024;
const MAX_OUTBOX = 1000;
const MAX_RECEIPTS = 10000;
const MAX_ROUTES = 4096;
const MAX_INFLIGHT = 8;

function privateFolder(folder) {
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(folder);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('channel state folder must be a directory, not a link');
  fs.chmodSync(folder, 0o700);
}

function readJson(file, maximum, privateOnly = false) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maximum ||
        (privateOnly && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()))) {
      throw new Error('channel file must be a bounded private regular file with one link');
    }
    const bytes = Buffer.alloc(maximum + 1);
    let size = 0;
    while (size <= maximum) {
      const got = fs.readSync(fd, bytes, size, maximum + 1 - size, null);
      if (got === 0) break;
      size += got;
    }
    if (size > maximum) throw new Error('channel file is too large');
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)));
  } finally { fs.closeSync(fd); }
}

export function readToken(file) {
  const value = readJson(file, 256 * 1024, true)?.MOBILE_APP_TOKEN;
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096) throw new Error('protected JSON secret file has no MOBILE_APP_TOKEN');
  return value;
}

function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }

export class ChannelTransport {
  constructor(account, { onMessage, onStop = () => {}, capabilities = [] }) {
    this.account = account;
    this.onMessage = onMessage;
    this.onStop = onStop;
    this.capabilities = capabilities;
    this.inflight = new Map();
    this.peer = null;
    this.server = null;
    this.closed = false;
    privateFolder(account.stateDir);
    this.file = path.join(account.stateDir, 'state.json');
    try { this.state = readJson(this.file, MAX_STATE_BYTES); }
    catch (error) {
      if (error.code !== 'ENOENT') throw new Error('cannot read enclos channel state; restore a valid state file before restarting', { cause: error });
      this.state = { v: 1, outbox: [], receipts: {}, routes: {} };
    }
    if (this.state.v !== 1 || !Array.isArray(this.state.outbox) || !this.state.receipts || !this.state.routes ||
        typeof this.state.receipts !== 'object' || Array.isArray(this.state.receipts) ||
        typeof this.state.routes !== 'object' || Array.isArray(this.state.routes) ||
        this.state.outbox.length > MAX_OUTBOX || Object.keys(this.state.receipts).length > MAX_RECEIPTS ||
        Object.keys(this.state.routes).length > MAX_ROUTES) throw new Error('unsupported or oversized enclos channel state');
    // Protocol identifiers such as __proto__ are data, never object setters.
    this.state.receipts = Object.assign(Object.create(null), this.state.receipts);
    this.state.routes = Object.assign(Object.create(null), this.state.routes);
    for (const [id, receipt] of Object.entries(this.state.receipts)) {
      checkedId(id);
      if (!receipt || !/^[0-9a-f]{64}$/.test(receipt.hash ?? '') || !['dispatching', 'received'].includes(receipt.status)) throw new Error('invalid enclos channel receipt');
    }
    for (const [conversation, route] of Object.entries(this.state.routes)) {
      checkedId(conversation, 'conversation'); checkedId(route?.person, 'person');
      if (route.peer !== digest([conversation, route.person])) throw new Error('invalid enclos channel conversation route');
    }
    for (const pending of this.state.outbox) {
      checkedId(pending?.id); checkedId(pending?.conversation, 'conversation');
      if (pending.v !== 1 || pending.type !== 'message.out' || typeof pending.text !== 'string' ||
          !['reply', 'notify', 'status'].includes(pending.kind)) throw new Error('invalid enclos channel outbox entry');
      if (pending.reply_to != null) checkedId(pending.reply_to, 'reply_to');
      encode(pending);
    }
    this.home = account.home;
  }

  save() {
    const bytes = Buffer.from(JSON.stringify(this.state));
    if (bytes.length > MAX_STATE_BYTES) throw new Error('channel state is full; no delivery was accepted');
    const temporary = path.join(this.account.stateDir, `.${randomUUID()}.tmp`);
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.renameSync(temporary, this.file);
    const folder = fs.openSync(this.account.stateDir, fs.constants.O_RDONLY);
    try { fs.fsyncSync(folder); } finally { fs.closeSync(folder); }
  }

  route(conversation, person) {
    checkedId(conversation, 'conversation'); checkedId(person, 'person');
    const current = this.state.routes[conversation];
    if (current && current.person !== person) throw new ProtocolError('not_allowed', 'conversation belongs to another person');
    if (current) return current;
    if (Object.keys(this.state.routes).length >= MAX_ROUTES) throw new Error('channel conversation registry is full');
    const route = { person, peer: digest([conversation, person]) };
    this.state.routes[conversation] = route;
    try { this.save(); } catch (error) { delete this.state.routes[conversation]; throw error; }
    return route;
  }

  send(conversation, text, { replyTo, kind } = {}) {
    if (this.closed) throw new Error('channel account is stopped');
    checkedId(conversation, 'conversation');
    if (typeof text !== 'string') throw new Error('outbound text must be text');
    if (replyTo != null) checkedId(replyTo, 'reply_to');
    if (this.state.outbox.length >= MAX_OUTBOX) throw new Error('too many replies waiting for the bridge');
    const outgoing = message('message.out', { conversation, text,
      kind: kind ?? (replyTo ? 'reply' : 'notify'), ...(replyTo ? { reply_to: replyTo } : {}) });
    encode(outgoing); // Reject before persistence.
    this.state.outbox.push(outgoing);
    try { this.save(); } catch (error) { this.state.outbox.pop(); throw error; }
    this.write(outgoing);
    return outgoing.id;
  }

  write(value, peer = this.peer) {
    if (!peer || peer.destroyed || !peer.authenticated) return false;
    const bytes = encode(value);
    if (peer.writableLength + bytes.length > MAX_STATE_BYTES) { peer.destroy(); return false; }
    peer.write(bytes);
    return true;
  }

  async start() {
    if (this.server) throw new Error('channel already started');
    readToken(this.account.tokenFile); // Missing/unreadable secrets never open a listener.
    privateFolder(path.dirname(this.account.socket));
    try {
      const stat = fs.lstatSync(this.account.socket);
      if (!stat.isSocket()) throw new Error('channel socket path is occupied by a non-socket');
      await new Promise((resolve, reject) => {
        const probe = net.createConnection(this.account.socket);
        probe.once('connect', () => { probe.destroy(); reject(new Error('channel socket is already in use')); });
        probe.once('error', error => error.code === 'ECONNREFUSED' ? resolve() : reject(error));
      });
      fs.unlinkSync(this.account.socket);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    this.server = net.createServer(peer => this.connect(peer));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.account.socket, resolve);
    });
    fs.chmodSync(this.account.socket, 0o600);
    this.socketIdentity = fs.lstatSync(this.account.socket);
  }

  connect(peer) {
    // Reserve the connection before authentication too; no two hellos race.
    if (this.peer || this.closed) { peer.destroy(); return; }
    this.peer = peer;
    let buffered = Buffer.alloc(0);
    const timer = setTimeout(() => peer.destroy(), 10000);
    timer.unref();
    peer.on('error', () => {});
    peer.on('close', () => { clearTimeout(timer); if (this.peer === peer) this.peer = null; });
    peer.on('data', bytes => {
      buffered = Buffer.concat([buffered, bytes]);
      while (!peer.destroyed) {
        const newline = buffered.indexOf(10);
        if (newline < 0) { if (buffered.length >= MAX_MESSAGE_BYTES) peer.destroy(); return; }
        const line = buffered.subarray(0, newline + 1);
        buffered = buffered.subarray(newline + 1);
        if (line.length > MAX_MESSAGE_BYTES) { peer.destroy(); return; }
        try {
          const incoming = decode(line);
          if (!peer.authenticated) {
            const token = readToken(this.account.tokenFile);
            if (incoming.type !== 'hello' || !tokenMatches(incoming.token, token)) { peer.destroy(); return; }
            peer.tokenDigest = digest(token);
            peer.authenticated = true; clearTimeout(timer);
            if (incoming.home) this.home = incoming.home;
            this.write(message('hello', { runtime: 'openclaw', agent: this.account.agentId, capabilities: this.capabilities }), peer);
            for (const pending of this.state.outbox) this.write(pending, peer);
          } else {
            if (peer.tokenDigest !== digest(readToken(this.account.tokenFile))) { peer.destroy(); return; }
            this.receive(incoming, peer);
          }
        } catch (error) {
          if (!peer.authenticated) { peer.destroy(); return; }
          this.write(message('error', { code: error.code ?? 'bad_message', message: 'invalid bridge message', ...(error.of ? { of: error.of } : {}) }), peer);
        }
      }
    });
  }

  receive(incoming, peer) {
    if (incoming.type === 'ack') {
      const index = this.state.outbox.findIndex(p => p.id === incoming.of);
      if (index >= 0) {
        const [removed] = this.state.outbox.splice(index, 1);
        try { this.save(); } catch (error) { this.state.outbox.splice(index, 0, removed); throw error; }
      }
      return;
    }
    if (incoming.type === 'error') return;
    if (incoming.type !== 'message.in') {
      this.write(message('error', { of: incoming.id, code: 'unsupported', message: 'this OpenClaw channel does not implement this control' }), peer);
      return;
    }
    this.accept(incoming).then(() => this.write(message('ack', { of: incoming.id }), peer)).catch(error => {
      this.write(message('error', { of: incoming.id, code: error.code ?? 'agent_unavailable',
        message: error instanceof ProtocolError ? error.message : 'native delivery could not be confirmed; refresh before intentionally sending again' }), peer);
    });
  }

  async accept(incoming) {
    if (incoming.attachments?.length) throw new ProtocolError('unsupported', 'this channel does not yet accept attachments');
    const hash = digest([incoming.conversation, incoming.person, incoming.text]);
    const old = this.state.receipts[incoming.id];
    if (old) {
      if (old.hash !== hash) throw new ProtocolError('conflict', 'message id was reused for different input');
      if (this.inflight.has(incoming.id)) return this.inflight.get(incoming.id);
      if (old.status === 'received') return;
      throw new ProtocolError('agent_unavailable', 'earlier native delivery is uncertain and will not be replayed');
    }
    if (this.inflight.size >= MAX_INFLIGHT || Object.keys(this.state.receipts).length >= MAX_RECEIPTS) throw new Error('channel receipt registry is full');
    const route = this.route(incoming.conversation, incoming.person);
    this.state.receipts[incoming.id] = { hash, status: 'dispatching' };
    try { this.save(); } catch (error) { delete this.state.receipts[incoming.id]; throw error; }
    const pending = Promise.resolve().then(() => this.onMessage(incoming, route, this)).then(() => {
      this.state.receipts[incoming.id].status = 'received';
      this.save();
    }).finally(() => this.inflight.delete(incoming.id));
    this.inflight.set(incoming.id, pending);
    return pending;
  }

  async close() {
    this.closed = true;
    this.peer?.destroy();
    this.onStop();
    if (this.server) await new Promise(resolve => this.server.close(resolve));
    try {
      const stat = fs.lstatSync(this.account.socket);
      if (stat.ino === this.socketIdentity?.ino && stat.dev === this.socketIdentity?.dev) fs.unlinkSync(this.account.socket);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}
