import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { inboundMedia, mediaFolder, stageMedia, MAX_MEDIA_BYTES } from '../media.js';
import { accountFixture } from './helpers.js';

test('local HTML keeps its bytes and travels as a bounded ordinary attachment', async t => {
  const account = accountFixture(t), folder = path.dirname(account.socket);
  const source = path.join(folder, 'page.html'), bytes = Buffer.from('<!doctype html><style>p{color:red}</style><p>Private page</p>');
  fs.writeFileSync(source, bytes);
  const sdk = { mediaRoots: () => [folder], async loadMedia(url, options) {
    assert.equal(url, source); assert.deepEqual(options.localRoots, [folder]);
    assert.equal(options.optimizeImages, false);
    return { buffer: fs.readFileSync(url), fileName: 'page.html', contentType: 'text/html' };
  } };
  const [attachment] = await stageMedia(account, [source], { sdk, cfg: {} });
  assert.equal(attachment.mime, 'text/html'); assert.equal(attachment.name, 'page.html');
  assert.equal(attachment.size, bytes.length); assert.ok(attachment.file.endsWith('.html'));
  assert.deepEqual(fs.readFileSync(path.join(mediaFolder(account), attachment.file)), bytes);
  assert.deepEqual(inboundMedia(account, [attachment], 'native-input'), [{ path: path.join(mediaFolder(account), attachment.file), contentType: 'text/html', messageId: 'native-input' }]);
});

test('attachment metadata cannot name another path, a link or a different-size file', t => {
  const account = accountFixture(t), folder = mediaFolder(account);
  fs.writeFileSync(path.join(folder, 'file.txt'), 'hello');
  const metadata = { file: 'file.txt', name: 'file.txt', size: 5, mime: 'text/plain' };
  assert.throws(() => inboundMedia(account, [{ ...metadata, file: '../host' }], 'id'));
  assert.throws(() => inboundMedia(account, [{ ...metadata, size: 6 }], 'id'));
  assert.throws(() => inboundMedia(account, [{ ...metadata, size: MAX_MEDIA_BYTES + 1 }], 'id'));
  fs.symlinkSync(path.join(folder, 'file.txt'), path.join(folder, 'linked.txt'));
  assert.throws(() => inboundMedia(account, [{ ...metadata, file: 'linked.txt' }], 'id'));
});

test('remote output is not fetched and revoked media preparation writes nothing', async t => {
  const account = accountFixture(t); let calls = 0;
  const sdk = { mediaRoots: () => [], async loadMedia() { calls++; return { buffer: Buffer.from('data'), fileName: 'file.txt', contentType: 'text/plain' }; } };
  await assert.rejects(stageMedia(account, ['https://example.invalid/private'], { sdk, cfg: {} }), /local permitted file/);
  assert.equal(calls, 0);
  let live = true;
  sdk.loadMedia = async () => { live = false; return { buffer: Buffer.from('data'), fileName: 'file.txt', contentType: 'text/plain' }; };
  await assert.rejects(stageMedia(account, ['/permitted/file.txt'], { sdk, cfg: {}, assertCurrent() { if (!live) throw new Error('revoked'); } }), /revoked/);
  assert.deepEqual(fs.readdirSync(mediaFolder(account)), []);
});
