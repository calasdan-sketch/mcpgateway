import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../src/ratelimit.js';
import { sleep } from '../src/util.js';
const rule = (rps, burst) => ({ rps, burst });
test('burst is allowed, then denied until refill', () => {
    const rl = new RateLimiter();
    assert.equal(rl.tryAcquire('t', rule(1, 3)), true);
    assert.equal(rl.tryAcquire('t', rule(1, 3)), true);
    assert.equal(rl.tryAcquire('t', rule(1, 3)), true);
    assert.equal(rl.tryAcquire('t', rule(1, 3)), false);
    assert.equal(rl.totalHits(), 1);
});
test('tokens refill over time', async () => {
    const rl = new RateLimiter();
    assert.equal(rl.tryAcquire('t', rule(1000, 1)), true);
    assert.equal(rl.tryAcquire('t', rule(1000, 1)), false);
    await sleep(10); // 1000 rps -> ~10 tokens refilled
    assert.equal(rl.tryAcquire('t', rule(1000, 1)), true);
});
test('keys are independent', () => {
    const rl = new RateLimiter();
    assert.equal(rl.tryAcquire('a', rule(1, 1)), true);
    assert.equal(rl.tryAcquire('a', rule(1, 1)), false);
    assert.equal(rl.tryAcquire('b', rule(1, 1)), true);
});
test('refill never exceeds burst', async () => {
    const rl = new RateLimiter();
    assert.equal(rl.tryAcquire('t', rule(1000, 2)), true);
    await sleep(20);
    // burst is 2: at most 2 available no matter how long we waited
    assert.equal(rl.tryAcquire('t', rule(1000, 2)), true);
    assert.equal(rl.tryAcquire('t', rule(1000, 2)), true);
    assert.equal(rl.tryAcquire('t', rule(1000, 2)), false);
});
test('pruneIdle drops stale buckets and keeps live ones', () => {
    const rl = new RateLimiter();
    rl.tryAcquire('old', rule(1, 1));
    rl.tryAcquire('new', rule(1, 1));
    assert.equal(rl.bucketCount(), 2);
    const removed = rl.pruneIdle(Date.now() + 11 * 60 * 1000);
    assert.equal(removed, 2);
    assert.equal(rl.bucketCount(), 0);
});
test('bucket count is bounded (no unbounded memory growth)', () => {
    const rl = new RateLimiter();
    for (let i = 0; i < 100_005; i++)
        rl.tryAcquire(`tool-${i}`, rule(1, 1));
    assert.ok(rl.bucketCount() <= 100_000, `bucketCount=${rl.bucketCount()}`);
    // limiter still functions at the cap
    assert.equal(rl.tryAcquire('tool-0-fresh', rule(1, 1)), true);
});
//# sourceMappingURL=ratelimit.test.js.map