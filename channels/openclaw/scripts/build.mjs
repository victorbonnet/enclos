import { readFileSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
const source = new URL('../index.ts', import.meta.url);
const output = new URL('../index.js', import.meta.url);
const javascript = stripTypeScriptTypes(readFileSync(source, 'utf8'), { mode: 'strip' }).replace(/[\t ]+$/gm, '');
if (process.argv.includes('--check')) {
  if (readFileSync(output, 'utf8') !== javascript) throw new Error('index.js is stale; run node scripts/build.mjs');
} else writeFileSync(output, javascript);
