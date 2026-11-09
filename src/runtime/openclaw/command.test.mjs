import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accessSync, constants, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const command = readFileSync(new URL('./command', import.meta.url), 'utf8');
let publicCaReadable = true;
try { accessSync('/etc/ssl/cert.pem', constants.R_OK); } catch { publicCaReadable = false; }

function launch(t, platform, overrides = {}) {
  const home = mkdtempSync(path.join(tmpdir(), 'enclos-openclaw-ca-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const bins = path.join(home, 'fake-bin'); mkdirSync(bins);
  writeFileSync(path.join(bins, 'uname'), `#!/bin/sh\nprintf '%s\\n' '${platform}'\n`, { mode: 0o700 });
  const native = path.join(home, '.local/share/openclaw/bin/openclaw');
  mkdirSync(path.dirname(native), { recursive: true });
  writeFileSync(native, '#!/bin/sh\nprintf \'%s\\n\' "${CODEX_CA_CERTIFICATE-<unset>}" "${SSL_CERT_FILE-<unset>}" "$@"\n', { mode: 0o700 });
  const result = spawnSync('/bin/sh', ['-c', command, 'openclaw', 'agent', '--message', 'exact spaced value'], {
    env: { HOME: home, HTTP_PROXY: 'http://127.0.0.1:41007', PATH: `${bins}:/usr/bin:/bin`, ...overrides }, encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const [codexCa, sslCa, ...args] = result.stdout.trimEnd().split('\n');
  assert.deepEqual(args, ['agent', '--message', 'exact spaced value']);
  return { codexCa, sslCa };
}

test('Darwin supplies public PEM roots to native Codex without changing its arguments', { skip: !publicCaReadable }, t => {
  assert.deepEqual(launch(t, 'Darwin'), { codexCa: '/etc/ssl/cert.pem', sslCa: '<unset>' });
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
