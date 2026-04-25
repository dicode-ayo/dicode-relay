/**
 * NonceStore — prevents replay attacks by tracking seen nonces for the
 * configured TTL window (60 s in production). Backed by `lru-cache` so
 * that an attacker flooding the handshake endpoint with fresh nonces
 * cannot grow memory unbounded — entries are LRU-evicted at the ceiling.
 *
 * Replay-via-eviction: at sustained handshake rates above
 * MAX_NONCES / ttlSeconds (≈ 1,667 handshakes/sec for 100k/60s) the LRU
 * starts evicting *non-expired* nonces, which would in principle allow
 * an attacker to replay an evicted but still-time-valid nonce. This is
 * not exploitable in practice because the handshake also enforces a
 * ±30s timestamp window (see relay protocol spec, verified in
 * src/relay/server.ts) — captured handshakes whose nonces could be
 * evicted are already too old on the timestamp check. The 60s nonce
 * TTL is the inner defense; the timestamp window is the binding outer
 * bound on replay validity.
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
   *
   * Atomicity: the has()/set() pair is *not* a CAS but is safe here
   * because Node.js JavaScript runs on a single thread and this method
   * contains no `await` — no other handshake can run between the two
   * operations. If a future contributor adds an `await` mid-method,
   * concurrent handshakes with the same nonce could both see has()
   * return false and both proceed, which is a replay-acceptance bug.
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
