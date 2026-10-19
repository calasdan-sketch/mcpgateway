/**
 * Token-bucket rate limiter with bounded memory.
 *
 * Buckets are created lazily per key; idle buckets are pruned, and a hard cap
 * on bucket count prevents unbounded growth from high-cardinality keys.
 */
import type { RateLimitRule } from './config.js';
export declare class RateLimiter {
    private buckets;
    private hits;
    /** Try to consume one token for key under rule. Returns true if allowed. */
    tryAcquire(key: string, rule: RateLimitRule): boolean;
    /** Remove buckets idle longer than IDLE_PRUNE_MS. Returns count removed. */
    pruneIdle(now?: number): number;
    bucketCount(): number;
    totalHits(): number;
    private evictOldestIdle;
}
//# sourceMappingURL=ratelimit.d.ts.map