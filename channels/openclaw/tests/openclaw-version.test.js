import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TESTED_OPENCLAW } from '../channel.js';
import { expectedOpenClawVersion, assertOpenClawVersion } from './openclaw-version.js';

test('default target accepts the exact tested release', () => {
  assert.equal(expectedOpenClawVersion({}), TESTED_OPENCLAW);
  assertOpenClawVersion(TESTED_OPENCLAW, expectedOpenClawVersion({}));
});
test('default target rejects a different installed release', () => {
  assert.throws(() => assertOpenClawVersion('2026.11.5', expectedOpenClawVersion({})), assert.AssertionError);
});
test('explicit stable target accepts its exact installed release', () => {
  const target = expectedOpenClawVersion({ ENCLOS_OPENCLAW_EXPECTED_VERSION: '2026.11.6' });
  assert.equal(target, '2026.11.6');
  assertOpenClawVersion('2026.11.6', target);
});
test('explicit target rejects a different installed release', () => {
  const target = expectedOpenClawVersion({ ENCLOS_OPENCLAW_EXPECTED_VERSION: '2026.11.6' });
  assert.throws(() => assertOpenClawVersion('2026.11.5', target), assert.AssertionError);
});
test('explicit empty or malformed targets fail instead of falling back', () => {
  for (const target of ['', ' ', 'latest', '^2026.11.6', '2026.11.6\n', ' 2026.11.6', '2026.11.6-', null]) {
    assert.throws(() => expectedOpenClawVersion({ ENCLOS_OPENCLAW_EXPECTED_VERSION: target }), /nonempty exact release version/);
  }
});
