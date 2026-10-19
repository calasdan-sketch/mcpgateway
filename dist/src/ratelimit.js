const IDLE_PRUNE_MS = 10 * 60 * 1000;
const MAX_BUCKETS = 100_000;
export class RateLimiter {
    buckets = new Map();
    hits = 0;
    /** Try to consume one token for key under rule. Returns true if allowed. */
    tryAcquire(key, rule) {
        const now = Date.now();
        let b = this.buckets.get(key);
        if (b === undefined) {
            if (this.buckets.size >= MAX_BUCKETS)
                this.evictOldestIdle(now);
            b = { tokens: rule.burst, lastRefill: now, lastSeen: now };
            this.buckets.set(key, b);
        }
        // Refill proportional to elapsed time.
        const elapsedSec = (now - b.lastRefill) / 1000;
        b.tokens = Math.min(rule.burst, b.tokens + elapsedSec * rule.rps);
        b.lastRefill = now;
        b.lastSeen = now;
        if (b.tokens >= 1) {
            b.tokens -= 1;
            return true;
        }
        this.hits += 1;
        return false;
    }
    /** Remove buckets idle longer than IDLE_PRUNE_MS. Returns count removed. */
    pruneIdle(now = Date.now()) {
        let removed = 0;
        for (const [k, b] of this.buckets) {
            if (now - b.lastSeen > IDLE_PRUNE_MS) {
                this.buckets.delete(k);
                removed += 1;
            }
        }
        return removed;
    }
    bucketCount() {
        return this.buckets.size;
    }
    totalHits() {
        return this.hits;
    }
    evictOldestIdle(now) {
        // At the cap: drop the single oldest-idle bucket to make room. The map is
        // non-empty here (we only evict at the cap), so oldestKey is always found
        // and the map stays exactly at MAX_BUCKETS.
        let oldestKey;
        let oldestSeen = Infinity;
        for (const [k, b] of this.buckets) {
            if (b.lastSeen < oldestSeen) {
                oldestSeen = b.lastSeen;
                oldestKey = k;
            }
        }
        if (oldestKey !== undefined)
            this.buckets.delete(oldestKey);
        void now;
    }
}
//# sourceMappingURL=ratelimit.js.map