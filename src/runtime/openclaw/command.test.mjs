import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accessSync, constants, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const command = readFileSync(new URL('./command', import.meta.url), 'utf8');
let publicCaReadable = true;
try { accessSync('/etc/ssl/cert.pem', constants.R_OK); } catch { publicCaReadable = false; }

function launch(t, platform, overrides = {}, args = ['agent', '--message', 'exact spaced value']) {
  const home = mkdtempSync(path.join(tmpdir(), 'enclos-openclaw-ca-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const bins = path.join(home, 'fake-bin'); mkdirSync(bins);
  writeFileSync(path.join(bins, 'uname'), `#!/bin/sh\nprintf '%s\\n' '${platform}'\n`, { mode: 0o700 });
  writeFileSync(path.join(bins, 'setsid'), '#!/bin/sh\n[ "$1" = --wait ] || exit 92\nshift\n: > "$HOME/new-session"\nexec "$@"\n', { mode: 0o700 });
  const native = path.join(home, '.local/share/openclaw/bin/openclaw');
  mkdirSync(path.dirname(native), { recursive: true });
  writeFileSync(native, '#!/bin/sh\nprintf \'%s\\n\' "${CODEX_CA_CERTIFICATE-<unset>}" "${SSL_CERT_FILE-<unset>}" "$@"\n', { mode: 0o700 });
  const result = spawnSync('/bin/sh', ['-c', command, 'openclaw', ...args], {
    env: { HOME: home, HTTP_PROXY: 'http://127.0.0.1:41007', PATH: `${bins}:/usr/bin:/bin`, ...overrides }, encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const [codexCa, sslCa, ...received] = result.stdout.trimEnd().split('\n');
  const gateway = args[0] === 'gateway' && args[1] === 'run';
  assert.deepEqual(received, gateway ? ['gateway', 'run', '--bind', 'loopback', '--port', '43007', ...args.slice(2)] : args);
  assert.equal(existsSync(path.join(home, 'new-session')), platform === 'Linux' && gateway);
  return { codexCa, sslCa };
}

test('Darwin supplies public PEM roots to native Codex without changing its arguments', { skip: !publicCaReadable }, t => {
  assert.deepEqual(launch(t, 'Darwin'), { codexCa: '/etc/ssl/cert.pem', sslCa: '<unset>' });
});

test('only the Linux background Gateway gets a new process session and preserves its arguments', t => {
  for (const platform of ['Linux', 'Darwin']) {
    launch(t, platform, {}, ['gateway', 'run', '--fixture', 'exact spaced value']);
  }
});

test('Linux keeps native TLS root selection', t => {
  assert.deepEqual(launch(t, 'Linux'), { codexCa: '<unset>', sslCa: '<unset>' });
});

test('explicit native and generic CA overrides take precedence on both platforms', t => {
  for (const platform of ['Darwin', 'Linux']) {
    assert.deepEqual(launch(t, platform, { CODEX_CA_CERTIFICATE: '/fixture/custom-codex.pem' }),
      { codexCa: '/fixture/custom-codex.pem', sslCa: '<unset>' });
    assert.deepEqual(launch(t, platform, { SSL_CERT_FILE: '/fixture/custom-generic.pem' }),
      { codexCa: '<unset>', sslCa: '/fixture/custom-generic.pem' });
  }
});
