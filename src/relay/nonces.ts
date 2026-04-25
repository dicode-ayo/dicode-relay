/**
 * NonceStore — prevents replay attacks by tracking seen nonces for the
 * configured TTL window (60 s in production). Backed by `lru-cache` so
 * that an attacker flooding the handshake endpoint with fresh nonces
 * cannot grow memory unbounded — entries are LRU-evicted at the ceiling.
 */

import { LRUCache } from "lru-cache";

/** Hard ceiling on tracked nonces. ~10x the expected steady-state churn. */
const MAX_NONCES = 100_000;

/**
 * `Date.now()`-backed clock used by LRUCache for TTL bookkeeping. Same
 * rationale as SessionStore: `vi.useFakeTimers()` patches the `Date`
 * global in place but *replaces* `performance` with a fake object, which
 * LRUCache's module-level `defaultPerf` reference would miss. Real-world
 * drift from system clock adjustments is acceptable for a 60 s anti-replay
 * window.
 */
const dateClock = {
  now: (): number => Date.now(),
};

type LruOpts = LRUCache.Options<string, true, unknown> & {
  perf?: { now(): number };
};

export class NonceStore {
  private readonly cache: LRUCache<string, true>;

  constructor(ttlMs: number) {
    const opts: LruOpts = {
      max: MAX_NONCES,
      ttl: ttlMs,
      // Eager eviction so `size` drops as entries expire — matches the
      // prior Map+setTimeout behavior the tests assert.
      ttlAutopurge: true,
      perf: dateClock,
    };
    this.cache = new LRUCache<string, true>(opts);
  }

  /**
   * Returns true if the nonce has been seen within the TTL window.
   * Registers the nonce so future calls return true.
   */
  check(nonce: string): boolean {
    if (this.cache.has(nonce)) {
      return true;
    }
    this.cache.set(nonce, true);
    return false;
  }

  /** Number of nonces currently tracked (for testing / observability). */
  get size(): number {
    return this.cache.size;
  }

  /** Clear all stored nonces (for testing). */
  clear(): void {
    this.cache.clear();
  }
}
