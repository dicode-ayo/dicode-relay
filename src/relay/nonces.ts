/**
 * NonceStore — prevents replay attacks by tracking seen nonces for the
 * configured TTL window (60 s in production). Backed by `lru-cache` so
 * that an attacker flooding the handshake endpoint with fresh nonces
 * cannot grow memory unbounded — entries are LRU-evicted at the ceiling.
 *
 * Replay-via-eviction: at sustained handshake rates above
 * MAX_NONCES / ttlSeconds (≈ 1,667 handshakes/sec for 100k/60s) the LRU
 * starts evicting non-expired nonces, which would in principle allow
 * replay of an evicted but still-time-valid nonce. The handshake also
 * enforces a ±30s timestamp window (see src/relay/server.ts), so a
 * captured handshake whose nonce could be evicted is already too old to
 * pass the timestamp check. The 60 s nonce TTL is the inner defense; the
 * timestamp window is the binding outer bound on replay validity.
 */

import { LRUCache } from "lru-cache";

/** Hard ceiling on tracked nonces. */
const MAX_NONCES = 100_000;

/**
 * `Date.now()`-backed clock used by LRUCache for TTL bookkeeping. Same
 * rationale as SessionStore: `vi.useFakeTimers()` patches the `Date`
 * global in place but replaces `performance` with a fake object, which
 * LRUCache's module-level `defaultPerf` reference would miss. Real-world
 * drift from system clock adjustments is acceptable for a 60 s
 * anti-replay window.
 */
const dateClock = {
  now: (): number => Date.now(),
};

// `perf` is accepted by the LRUCache constructor but not exposed in the
// public type definitions, so we pass options as a partial record and
// let LRUCache consume the runtime property.
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
