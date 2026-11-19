import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_RUNS, registerUsage } from '../usage.js';

// A connected agent's account, its bridge taking `capabilities`.
function account(agentId, capabilities = ['usage', 'agent_usage']) {
  const sent = [];
  return { sent, active: { account: { agentId, accountId: agentId },
    transport: { closed: false, bridgeCapabilities: new Set(capabilities), write(m) { sent.push(m); return true; } } } };
}

function setup({ config = { plugins: { entries: { enclos: { hooks: { allowConversationAccess: true } } } } }, accounts = [account('main')], appTurn = () => undefined } = {}) {
  const hooks = new Map(), warnings = [];
  const running = new Map(accounts.map(a => [a.active.account.accountId, a.active]));
  const reported = registerUsage({ config, logger: { warn: text => warnings.push(text) }, on(name, callback) { hooks.set(name, callback); } },
    { appTurn, appSession: ctx => ctx?.messageProvider === 'enclos', assertTurn() {}, running });
  const ended = (runId, outcome = 'completed') => hooks.get('model_call_ended')({ runId, callId: `${runId}-${Math.random()}`, outcome }, {});
  const output = (event, ctx = { agentId: 'main', trigger: 'cron' }) => hooks.get('llm_output')(event, ctx);
  return { reported, hooks, warnings, ended, output };
}

test('without allowConversationAccess, OpenClaw would drop llm_output: no usage is announced, and that is said once', () => {
  for (const config of [{}, { plugins: { entries: { enclos: { hooks: { allowConversationAccess: false } } } } }]) {
    const s = setup({ config });
    assert.equal(s.reported, false);
    assert.equal(s.hooks.size, 0);
    assert.equal(s.warnings.length, 1);
    assert.match(s.warnings[0], /allowConversationAccess/);
  }
});

test('each attempt reports its own completed calls, and a report without tokens still clears its count', () => {
  const main = account('main'), s = setup({ accounts: [main] });
  s.ended('run'); s.ended('run'); s.ended('run', 'error');
  s.output({ runId: 'run', usage: { input: 1 } });
  for (let i = 0; i < 3; i++) s.ended('run');
  s.output({ runId: 'run', usage: { input: 1 } });
  // Never 5: the first attempt's calls were reported with it.
  assert.deepEqual(main.sent.map(m => m.calls), [2, 3]);
  s.ended('quiet'); s.ended('quiet');
  s.output({ runId: 'quiet' });
  s.output({ runId: 'quiet', usage: { input: 1 } });
  // One call: absent `calls`.
  assert.equal(main.sent.at(-1).calls, undefined);
  assert.equal(s.warnings.length, 0);
});

test('past the runs counted at once, the oldest is forgotten and a run that saw a call lately is kept', () => {
  const main = account('main'), s = setup({ accounts: [main] });
  s.ended('old'); s.ended('old');
  s.ended('kept'); s.ended('kept');
  for (let i = 0; i < MAX_RUNS - 2; i++) s.ended(`run-${i}`);
  s.ended('kept');
  s.ended('newest'); s.ended('newest');
  s.output({ runId: 'old', usage: { input: 1 } });
  s.output({ runId: 'kept', usage: { input: 1 } });
  assert.deepEqual(main.sent.map(m => m.calls), [undefined, 3]);
});

test('a call outside the app goes only to its own agent\'s connection, and only to a bridge that takes it', () => {
  const main = account('main'), scout = account('scout'), older = account('writer', ['usage']);
  const s = setup({ accounts: [main, scout, older] });
  s.output({ usage: { input: 3 } }, { agentId: 'scout', trigger: 'cron' });
  s.output({ usage: { input: 4 } }, { agentId: 'writer', messageProvider: 'telegram' });
  s.output({ usage: { input: 5 } }, { agentId: 'nobody', trigger: 'cron' });
  assert.deepEqual(main.sent, []);
  assert.deepEqual(scout.sent.map(m => [m.type, m.tokens.input, m.source]), [['usage.agent', 3, 'cron']]);
  assert.deepEqual(older.sent, []);
  // An app call whose conversation cannot be told is not sent, and is said once.
  s.output({ usage: { input: 6 } }, { agentId: 'main', messageProvider: 'enclos' });
  s.output({ usage: { input: 6 } }, { agentId: 'main', messageProvider: 'enclos' });
  assert.deepEqual(main.sent, []);
  assert.equal(s.warnings.length, 1);
});

test('names are cut to the protocol\'s lengths on one line, calls to the bridge\'s bound, and a failure is said by kind once', () => {
  const main = account('main');
  const s = setup({ accounts: [main] });
  for (let i = 0; i < 1200; i++) s.ended('long');
  s.output({ runId: 'long', model: `m\n${'x'.repeat(200)}`, provider: 'p'.repeat(100), usage: { input: 1, output: -1, cacheRead: 1.5 } },
    { agentId: 'main', messageProvider: 's'.repeat(50) });
  const [sent] = main.sent;
  assert.equal(sent.model.length, 120);
  assert.ok(sent.model.startsWith('m x'));
  assert.equal(sent.model_provider.length, 64);
  assert.equal(sent.source.length, 32);
  assert.equal(sent.calls, 1000);
  assert.deepEqual(sent.tokens, { input: 1 });
  const failing = setup({ appTurn: () => { throw new TypeError('secret detail'); } });
  failing.output({ usage: { input: 1 } });
  failing.output({ usage: { input: 1 } });
  assert.deepEqual(failing.warnings, ['[enclos] a model call\'s usage was not passed on (TypeError)']);
});
