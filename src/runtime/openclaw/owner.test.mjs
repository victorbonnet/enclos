import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const owner = readFileSync(new URL('./owner', import.meta.url), 'utf8');

// A stand-in for `openclaw config get|set commands.ownerAllowFrom`, with the
// list in a file and OpenClaw's compare-and-set flags.
const fake = `#!/bin/sh
list="$HOME/owners.json"
[ "$1 $2 $3" = "config get commands.ownerAllowFrom" ] && { [ -f "$list" ] || exit 1; cat "$list"; exit 0; }
[ "$1 $2 $3" = "config set commands.ownerAllowFrom" ] || exit 90
value=$4; shift 4
[ "$1" = --strict-json ] || exit 91
case "$2" in
  --expect-current-absent) [ ! -f "$list" ] || exit 1 ;;
  --expect-current-json) [ "$(cat "$list")" = "$3" ] || exit 1 ;;
  *) exit 92 ;;
esac
printf '%s' "$value" > "$list"
`;

function run(t, before) {
  const home = mkdtempSync(path.join(tmpdir(), 'enclos-openclaw-owner-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(path.join(home, 'bin'));
  writeFileSync(path.join(home, 'bin/openclaw'), fake, { mode: 0o700 });
  const node = path.join(home, '.local/share/openclaw/tools/node/bin/node');
  mkdirSync(path.dirname(node), { recursive: true });
  symlinkSync(process.execPath, node);
  if (before !== undefined) writeFileSync(path.join(home, 'owners.json'), before);
  const result = spawnSync('/bin/sh', ['-c', owner, 'enclos-openclaw-owner'], { env: { HOME: home, PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
  const list = path.join(home, 'owners.json');
  return { status: result.status, stderr: result.stderr, after: existsSync(list) ? readFileSync(list, 'utf8') : undefined };
}

test('with no owner, the channel\'s sender becomes the only one', t => {
  const { status, stderr, after } = run(t);
  assert.equal(status, 0, stderr);
  assert.deepEqual(JSON.parse(after), ['enclos:host']);
});

test('another owner is kept, and the entry is added once', t => {
  const first = run(t, '["telegram:42"]');
  assert.equal(first.status, 0, first.stderr);
  assert.deepEqual(JSON.parse(first.after), ['telegram:42', 'enclos:host']);
  const again = run(t, first.after);
  assert.equal(again.status, 0, again.stderr);
  assert.equal(again.after, first.after);
  assert.equal(run(t, '[" Enclos:Host "]').after, '[" Enclos:Host "]');
});

test('a list that is not a list is refused and left as it was', t => {
  const { status, after } = run(t, '{"telegram":"42"}');
  assert.notEqual(status, 0);
  assert.equal(after, '{"telegram":"42"}');
});
