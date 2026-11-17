// Rate limiter tests: sliding window, expiry, reset, retry hint.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRateLimiter } from '../src/lib/ratelimit.js';

function setup(options = {}) {
  let clock = 1_000_000;
  const rl = createRateLimiter({ limit: 3, windowMs: 1000, now: () => clock, ...options });
  return { rl, tick: (ms) => (clock += ms) };
}

test('ratelimit: blocks after the configured number of failures', () => {
  const { rl } = setup();
  assert.equal(rl.isBlocked('a'), false);
  assert.equal(rl.fail('a'), false);
  assert.equal(rl.fail('a'), false);
  assert.equal(rl.isBlocked('a'), false);
  assert.equal(rl.fail('a'), true);
  assert.equal(rl.isBlocked('a'), true);
  // Independent keys do not affect each other.
  assert.equal(rl.isBlocked('b'), false);
});

test('ratelimit: the window slides', () => {
  const { rl, tick } = setup();
  rl.fail('a');
  rl.fail('a');
  rl.fail('a');
  assert.equal(rl.isBlocked('a'), true);
  tick(1001);
  assert.equal(rl.isBlocked('a'), false, 'old attempts left the window');
  assert.equal(rl.fail('a'), false, 'fresh attempt is counted again');
});

test('ratelimit: reset clears a key (successful pairing)', () => {
  const { rl } = setup();
  rl.fail('a');
  rl.fail('a');
  rl.fail('a');
  assert.equal(rl.isBlocked('a'), true);
  rl.reset('a');
  assert.equal(rl.isBlocked('a'), false);
});

test('ratelimit: retryAfterSeconds reports the remaining wait', () => {
  const { rl, tick } = setup();
  rl.fail('a');
  rl.fail('a');
  assert.equal(rl.retryAfterSeconds('a'), 0, 'below the limit');
  rl.fail('a');
  assert.equal(rl.retryAfterSeconds('a'), 1);
  tick(400);
  assert.equal(rl.retryAfterSeconds('a'), 1);
  tick(600);
  assert.equal(rl.retryAfterSeconds('a'), 0);
});
