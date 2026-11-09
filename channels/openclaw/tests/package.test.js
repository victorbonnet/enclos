import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

test('every shipped JavaScript module retains its relative import dependencies', () => {
  const root = new URL('../', import.meta.url);
  const manifest = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
  const shipped = new Set(manifest.files);
  for (const file of shipped) {
    if (!file.endsWith('.js')) continue;
    const source = readFileSync(new URL(file, root), 'utf8');
    // Shipped modules use literal ESM imports. Include re-exports, side-effect
    // imports and literal dynamic imports without evaluating native SDK code.
    for (const match of source.matchAll(/\b(?:from\s+|import\s*(?:\(\s*)?)(['"])(\.\.?\/[^'"]+)\1/gu)) {
      const dependency = path.posix.normalize(path.posix.join(path.posix.dirname(file), match[2]));
      assert.ok(shipped.has(dependency), `${file} imports ${match[2]}, absent from package.files`);
    }
  }
});
