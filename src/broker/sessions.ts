/**
 * OAuth broker flow-state types and single-use guard.
 *
 * The flow payload is no longer held in a shared in-process map — it is sealed
 * into a browser cookie so the flow survives a load balancer (see
 * `broker/flow-state.ts`). What remains here is the `Session` payload shape and
 * `SeenSet`, a per-instance LRU that enforces single-use best-effort: a session
 * id consumed on one instance cannot be replayed against that same instance.
 * Cross-instance replay is bounded by the short flow TTL and accepted.
 */

import { LRUCache } from "lru-cache";

export interface Session {
  /** UUID v4 of the broker session */
  sessionId: string;
  /** UUID (64 hex chars) of the connected daemon */
  relayUuid: string;
  /** 65-byte uncompressed P-256 public key of the daemon (ECIES recipient) */
  pubkey: Buffer;
  /** base64url-encoded PKCE challenge */
  pkceChallenge: string;
  /** Provider key (e.g. "github") */
  provider: string;
  /** Unix timestamp when this session expires */
  expiresAt: number;
  /** Override scopes requested by task.ts */
  scope?: string | undefined;
}

/** Hard ceiling on tracked session ids. */
const MAX_SEEN = 10_000;

/**
 * Monotonic-ish clock used by LRUCache for TTL bookkeeping. We route
 * through `Date.now()` (looked up dynamically at call time) rather than
 * `performance.now()` so that fake-timer-based tests remain deterministic:
 * `vi.useFakeTimers()` patches the `Date` global in place, but `performance`
 * gets *replaced* with a fake object, which LRUCache's module-level
 * `defaultPerf` reference would miss. Real-world drift from system clock
 * adjustments is acceptable for a 5-minute OAuth session TTL.
 */
const dateClock = {
  now: (): number => Date.now(),
};

// `perf` is accepted by the LRUCache constructor but not exposed in the
// public type definitions, so we pass the options as a partial record and
// let LRUCache consume the runtime property.
type LruOpts = LRUCache.Options<string, true, unknown> & {
  perf?: { now(): number };
};

/**
 * Per-instance single-use guard for OAuth session ids. Bounded LRU with a TTL
 * matching the flow lifetime, so a consumed id is remembered just long enough
 * to reject a replay within the window where the sealed token is still valid.
 */
export class SeenSet {
  private readonly cache: LRUCache<string, true>;

  constructor(ttlMs: number) {
    const opts: LruOpts = {
      max: MAX_SEEN,
      ttl: ttlMs,
      ttlAutopurge: true,
      perf: dateClock,
    };
    this.cache = new LRUCache<string, true>(opts);
  }

  /**
   * Record `id` as consumed. Returns true if it was newly recorded, false if
   * `id` was already present (i.e. this is a replay).
   */
  add(id: string): boolean {
    if (this.cache.has(id)) return false;
    this.cache.set(id, true);
    return true;
  }

  /** Whether `id` has been recorded (and not yet expired). */
  has(id: string): boolean {
    return this.cache.has(id);
  }

  /** Number of tracked ids (for testing / observability). */
  get size(): number {
    return this.cache.size;
  }

  /** Clear all tracked ids (for testing). */
  clear(): void {
    this.cache.clear();
  }
}
