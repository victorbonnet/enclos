import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createNativeTurns } from '../native-turns.js';

test('abort owns an exact ingress and cannot stop its same-conversation successor', () => {
  let current = true;
  const turns = createNativeTurns(() => { if (!current) throw new Error('retired'); });
  const first = turns.begin({ id: 'first', conversation: 'c' });
  const second = turns.begin({ id: 'second', conversation: 'c' });
  const other = turns.begin({ id: 'other', conversation: 'd' });
  const abort = (of, conversation = 'c') => turns.handleControl({ type: 'turn.abort', of, conversation });
  abort('first', 'd'); assert.equal(first.signal.aborted, false);
  abort('first'); abort('first'); assert.equal(first.signal.aborted, true);
  assert.equal(second.signal.aborted, false); assert.equal(other.signal.aborted, false);
  first.finish(); abort('first'); assert.equal(second.signal.aborted, false);
  second.finish(); abort('second'); assert.equal(other.signal.aborted, false);
  current = false; assert.throws(() => abort('other', 'd'), /retired/); assert.equal(other.signal.aborted, false);
  turns.close(); assert.equal(other.signal.aborted, true);
});
