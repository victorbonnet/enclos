// Files cross the existing enclos media-folder seam. OpenClaw retains read policy.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const MAX_MEDIA_BYTES = 25 * 1024 * 1024;
const MAX_FILES = 10;
const plain = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u;

export function mediaFolder(account) {
  const folder = path.join(path.dirname(account.socket), 'media');
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(folder);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('channel media folder must be a plain directory');
  fs.chmodSync(folder, 0o700);
  return folder;
}

function metadata(value) {
  if (!value || !plain.test(value.file ?? '') || typeof value.mime !== 'string' ||
      !/^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/u.test(value.mime) ||
      typeof value.name !== 'string' || Buffer.byteLength(value.name) > 256 || /[\x00-\x1f\x7f-\x9f]/u.test(value.name) ||
      !Number.isSafeInteger(value.size) || value.size < 0 || value.size > MAX_MEDIA_BYTES) throw new Error('invalid channel attachment');
}

export function inboundMedia(account, attachments = [], messageId) {
  if (!Array.isArray(attachments) || attachments.length > MAX_FILES) throw new Error('a message carries at most ten files');
  const folder = mediaFolder(account); let total = 0;
  return attachments.map(attachment => {
    metadata(attachment); total += attachment.size;
    if (total > MAX_MEDIA_BYTES) throw new Error('message attachments exceed 25 MiB');
    const file = path.join(folder, attachment.file);
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size !== attachment.size) throw new Error('attachment is not the declared regular file');
    } finally { fs.closeSync(fd); }
    return { path: file, contentType: attachment.mime, messageId };
  });
}

export async function stageMedia(account, urls, { sdk, cfg, access = {}, assertCurrent = () => {} }) {
  if (!Array.isArray(urls) || urls.length > MAX_FILES) throw new Error('a message carries at most ten files');
  const folder = mediaFolder(account); let total = 0; const staged = [];
  try {
    for (const url of urls) {
      // Remote assets are never fetched merely because they occur in output.
      // The agent can save a permitted download first, through its own tools.
      if (typeof url !== 'string' || (/^[a-z][a-z0-9+.-]*:/iu.test(url) && !url.startsWith('file:'))) throw new Error('save media to a local permitted file before sending it through enclos');
      const roots = access.mediaAccess?.localRoots ?? access.mediaLocalRoots ?? sdk.mediaRoots(cfg, account.agentId, access.mediaAccess?.workspaceDir);
      if (!Array.isArray(roots)) throw new Error('native media access did not provide scoped local roots');
      assertCurrent();
      const media = await sdk.loadMedia(url, { maxBytes: MAX_MEDIA_BYTES - total, optimizeImages: false,
        localRoots: roots, readFile: access.mediaAccess?.readFile ?? access.mediaReadFile,
        workspaceDir: access.mediaAccess?.workspaceDir });
      assertCurrent();
      if (!Buffer.isBuffer(media.buffer)) throw new Error('native media reader did not return bytes');
      total += media.buffer.length;
      if (total > MAX_MEDIA_BYTES) throw new Error('message attachments exceed 25 MiB');
      const characters = [...path.basename(media.fileName ?? url).replace(/[\x00-\x1f\x7f-\x9f]/gu, '_')];
      while (Buffer.byteLength(characters.join('')) > 240) characters.pop();
      const name = characters.join('') || 'attachment';
      const extension = /^\.[a-zA-Z0-9]{1,12}$/u.test(path.extname(name)) ? path.extname(name) : '.bin';
      const attachment = { file: `${randomUUID()}${extension}`, mime: (media.contentType ?? 'application/octet-stream').split(';')[0], name, size: media.buffer.length };
      metadata(attachment);
      const target = path.join(folder, attachment.file);
      const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { fs.writeFileSync(fd, media.buffer); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      staged.push(attachment);
    }
    return staged;
  } catch (error) {
    for (const attachment of staged) fs.rmSync(path.join(folder, attachment.file), { force: true });
    throw error;
  }
}
