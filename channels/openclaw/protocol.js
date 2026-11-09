// The enclos plugin leg. Runtime-specific behavior belongs in channel.js.
import { randomUUID, timingSafeEqual } from 'node:crypto';

export const VERSION = 1;
export const MAX_MESSAGE_BYTES = 1024 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });
const known = new Set(['hello', 'message.in', 'ack', 'error', 'policy.context',
  'conversation.rename', 'routine.request', 'question.answer', 'question.sync']);

export class ProtocolError extends Error {
  constructor(code, message, of) { super(message); this.code = code; this.of = of; }
}

export function checkedId(value, name = 'id') {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 128 || /[\x00-\x1f\x7f-\x9f]/u.test(value)) {
    throw new Error(`${name} must be a nonempty printable identifier of at most 128 bytes`);
  }
  return value;
}

export function decode(line) {
  if ((typeof line === 'string' ? Buffer.byteLength(line) : line.byteLength) > MAX_MESSAGE_BYTES) throw new ProtocolError('bad_message', 'larger than 1 MiB');
  let value;
  try { value = JSON.parse(typeof line === 'string' ? line : utf8.decode(line)); }
  catch { throw new ProtocolError('bad_message', 'not UTF-8 JSON'); }
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new ProtocolError('bad_message', 'not a JSON object');
  let of;
  try { of = checkedId(value.id); } catch { /* An invalid id is never echoed. */ }
  if (value.v !== VERSION) throw new ProtocolError(Number.isInteger(value.v) ? 'version' : 'bad_message', 'unsupported or missing version', of);
  if (typeof value.type !== 'string') throw new ProtocolError('bad_message', 'no type', of);
  if (!known.has(value.type)) throw new ProtocolError('unknown_type', 'unknown message type', of);
  try {
    checkedId(value.id);
    if (value.type === 'hello') {
      if (typeof value.token !== 'string') throw new Error('token must be text');
      if (value.home != null) checkedId(value.home, 'home');
      if (value.capabilities != null && (!Array.isArray(value.capabilities) || !value.capabilities.every(c => typeof c === 'string'))) throw new Error('capabilities must be strings');
    } else if (value.type === 'message.in') {
      checkedId(value.conversation, 'conversation'); checkedId(value.person, 'person');
      if (typeof value.text !== 'string') throw new Error('text must be text');
      if (value.attachments != null && !Array.isArray(value.attachments)) throw new Error('attachments must be an array');
    } else if (value.type === 'ack') checkedId(value.of, 'of');
    else if (value.type === 'conversation.rename') {
      checkedId(value.conversation, 'conversation');
      if (typeof value.title !== 'string') throw new Error('title must be text');
    } else if (value.type === 'error' && (typeof value.code !== 'string' || typeof value.message !== 'string')) throw new Error('error fields must be text');
  } catch (error) { throw new ProtocolError('bad_message', error.message, of); }
  return value;
}

export function message(type, fields = {}) { return { v: VERSION, id: randomUUID(), type, ...fields }; }
export function encode(value) {
  const bytes = Buffer.from(JSON.stringify(value) + '\n');
  if (bytes.byteLength > MAX_MESSAGE_BYTES) throw new ProtocolError('bad_message', 'larger than 1 MiB');
  return bytes;
}
export function tokenMatches(presented, expected) {
  if (typeof presented !== 'string' || !expected) return false;
  const left = Buffer.from(presented), right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
