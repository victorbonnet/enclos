import assert from 'node:assert/strict';
import test from 'node:test';
import { assertIdleBinding, bindingForAgent, mergeAuth } from './transfer-native.mjs';

test('inherited logins become local without replacing own profile priority', () => {
  const target = { version: 1, profiles: { own: { key: 'own' } }, order: { openai: ['own'] } };
  const inherited = { profiles: { own: { key: 'shared' }, base: { key: 'base' } }, order: { openai: ['base'] } };
  const own = { profiles: { resolved: { key: 'materialized' } }, lastGood: { openai: 'own' } };
  assert.equal(mergeAuth(target, inherited, own), true);
  assert.deepEqual(target.profiles, { own: { key: 'own' }, base: { key: 'base' }, resolved: { key: 'materialized' } });
  assert.deepEqual(target.order.openai, ['own']);
  assert.equal(target.lastGood.openai, 'own');
  assert.equal(inherited.profiles.own.key, 'shared');
});

test('binding selection respects complete native agent id boundaries', () => {
  for (const key of ['session-key:main:hash', 'session:main:id']) assert.equal(bindingForAgent(key, 'main'), true);
  for (const key of ['session-key:main-other:hash', 'session:kilian:id', 'conversation:main']) assert.equal(bindingForAgent(key, 'main'), false);
});

test('an active lease or unresolved native subagent work cannot be migrated', () => {
  assert.doesNotThrow(() => assertIdleBinding({ binding: { threadId: 'completed' }, lease: { expiresAt: 1 } }, 2));
  for (const value of [null, { lease: {} }, { lease: { expiresAt: 3 } },
    { binding: { pendingSupervisionBranch: {} } },
    { nativeSubagentAssignments: { assignments: [{}] } },
    { nativeSubagentSubmissions: { receipts: [{}] } }, { nativeSubagentTaskImport: {} }]) {
    assert.throws(() => assertIdleBinding(value, 2));
  }
});
