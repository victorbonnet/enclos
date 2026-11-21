import assert from 'node:assert/strict';
import { TESTED_OPENCLAW } from '../channel.js';

// An explicit exact-version expectation is independent of the observed package.
export function expectedOpenClawVersion(env = process.env) {
  const target = env.ENCLOS_OPENCLAW_EXPECTED_VERSION;
  if (target === undefined) return TESTED_OPENCLAW;
  if (typeof target !== 'string' || !/^\d{4}\.\d{1,2}\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(target)) {
    throw new Error('ENCLOS_OPENCLAW_EXPECTED_VERSION must be a nonempty exact release version');
  }
  return target;
}

export function assertOpenClawVersion(installed, expected = expectedOpenClawVersion()) {
  assert.equal(installed, expected, 'installed OpenClaw must match the expected exact version');
}
