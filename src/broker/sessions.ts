/**
 * SessionStore — in-memory store for OAuth broker sessions.
 * Each session is created when the daemon initiates an OAuth flow and is
 * deleted immediately after the token is delivered.
 *
 * TTL: configurable per instance (5 minutes in production). Sessions that
 * have not been completed by then are purged. Storage is an `lru-cache` with
 * a hard max of 10_000 entries to bound memory against abusive traffic.
 */

import { LRUCache } from "lru-cache";

export interface Session {
  /** UUID v4 of the broker session */
  sessionId: string;
  /** UUID (64 hex chars) of the connected daemon */
  relayUuid: string;
  /** 65-byte uncompressed P-256 public key of the daemon */
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

/** Hard ceiling on concurrent in-flight OAuth sessions. */
const MAX_SESSIONS = 10_000;

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
type LruOpts = LRUCache.Options<string, Session, unknown> & {
  perf?: { now(): number };
};

export class SessionStore {
  private readonly cache: LRUCache<string, Session>;

  constructor(ttlMs: number) {
    const opts: LruOpts = {
      max: MAX_SESSIONS,
      ttl: ttlMs,
      // Schedule a setTimeout per entry so expired sessions are dropped
      // eagerly (preserves prior Map+setTimeout behavior: `size` drops to 0
      // at TTL without needing a subsequent `get`).
      ttlAutopurge: true,
      perf: dateClock,
    };
    this.cache = new LRUCache<string, Session>(opts);
  }

  /**
   * Store a new session. Replaces any existing session with the same ID
   * (and resets its TTL). Automatically expires after the configured TTL.
   */
  set(session: Session): void {
    this.cache.set(session.sessionId, session);
  }

  /**
   * Retrieve a session by ID.
   * Returns undefined if not found or expired.
   */
  get(sessionId: string): Session | undefined {
    return this.cache.get(sessionId);
  }

  /**
   * Delete a session by ID (e.g., after successful token delivery).
   * Idempotent — does nothing if not found.
   */
  delete(sessionId: string): void {
    this.cache.delete(sessionId);
  }

  /** Number of active sessions (for testing / observability). */
  get size(): number {
    return this.cache.size;
  }

  /** Clear all sessions (for testing). */
  clear(): void {
    this.cache.clear();
  }
}
