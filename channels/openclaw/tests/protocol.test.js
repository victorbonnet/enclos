import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, chmodSync, symlinkSync, linkSync } from 'node:fs';
import path from 'node:path';
import { checkedId, decode, encode, MAX_MESSAGE_BYTES, message, tokenMatches } from '../protocol.js';
import { readToken } from '../transport.js';
import { accountFixture } from './helpers.js';

test('Rust and Hermes protocol fixtures retain their JSON and unknown fields', () => {
  const fixtures = new URL('../../../crates/enclos-protocol/tests/fixtures/plugin/', import.meta.url);
  for (const name of readdirSync(fixtures)) {
    const original = JSON.parse(readFileSync(new URL(name, fixtures), 'utf8'));
    assert.deepEqual(JSON.parse(encode(original)), original, name);
    if (name.startsWith('from_bridge')) assert.deepEqual(decode(encode(original)), original, name);
  }
});

test('wire distinguishes unknown types from malformed known messages and limits UTF-8 bytes', () => {
  assert.throws(() => decode(Buffer.from([0xff])), e => e.code === 'bad_message');
  assert.throws(() => decode(Buffer.from('[]')), e => e.code === 'bad_message');
  assert.throws(() => decode(encode(message('next-version'))), e => e.code === 'unknown_type');
  assert.throws(() => decode(JSON.stringify({ v: 1, id: 'x'.repeat(5000), type: 'unknown' })), e => e.code === 'unknown_type' && e.of === undefined);
  assert.throws(() => decode('x'.repeat(MAX_MESSAGE_BYTES + 1)), e => e.code === 'bad_message');
  assert.throws(() => decode(encode(message('message.in', { conversation: 'c', person: 'p' }))), e => e.code === 'bad_message');
  assert.throws(() => decode(encode({ ...message('ack', { of: 'known' }), v: 2 })), e => e.code === 'version');
  assert.throws(() => checkedId('😀'.repeat(33)));
  assert.throws(() => checkedId('bad\x1b'));
  assert.equal(checkedId('__proto__'), '__proto__');
  assert.throws(() => encode(message('message.out', { text: 'x'.repeat(MAX_MESSAGE_BYTES) })));
  assert.equal(tokenMatches('one', 'one'), true);
  assert.equal(tokenMatches('one', 'two'), false);
  assert.equal(tokenMatches('', ''), false);
});

test('JSON token files require private single-link regular files', t => {
  const account = accountFixture(t);
  assert.equal(readToken(account.tokenFile), 'only-for-tests');
  chmodSync(account.tokenFile, 0o644);
  assert.throws(() => readToken(account.tokenFile));
  chmodSync(account.tokenFile, 0o600);
  const alias = path.join(path.dirname(account.tokenFile), 'alias');
  symlinkSync(account.tokenFile, alias);
  assert.throws(() => readToken(alias));
  linkSync(account.tokenFile, `${alias}-hard`);
  assert.throws(() => readToken(account.tokenFile));
});
