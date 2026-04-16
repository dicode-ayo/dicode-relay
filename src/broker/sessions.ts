/**
 * SessionStore — in-memory store for OAuth broker sessions.
 * Each session is created when the daemon initiates an OAuth flow and is
 * deleted immediately after the token is delivered.
 *
 * TTL: 5 minutes. Sessions that have not been completed by then are purged.
 */

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

export class SessionStore {
  private readonly store = new Map<string, Session>();
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly ttlMs: number;

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  /**
   * Store a new session. Replaces any existing session with the same ID.
   * Automatically expires after the configured TTL.
   */
  set(session: Session): void {
    // Clear any existing timer for this session ID
    const existing = this.timers.get(session.sessionId);
    if (existing !== undefined) {
      clearTimeout(existing);
    }

    this.store.set(session.sessionId, session);

    const timer = setTimeout(() => {
      this.store.delete(session.sessionId);
      this.timers.delete(session.sessionId);
    }, this.ttlMs);
    timer.unref();

    this.timers.set(session.sessionId, timer);
  }

  /**
   * Retrieve a session by ID.
   * Returns undefined if not found or expired.
   */
  get(sessionId: string): Session | undefined {
    return this.store.get(sessionId);
  }

  /**
   * Delete a session by ID (e.g., after successful token delivery).
   * Idempotent — does nothing if not found.
   */
  delete(sessionId: string): void {
    const timer = this.timers.get(sessionId);
    if (timer !== undefined) {
      clearTimeout(timer);
      this.timers.delete(sessionId);
    }
    this.store.delete(sessionId);
  }

  /** Number of active sessions (for testing / observability). */
  get size(): number {
    return this.store.size;
  }

  /** Clear all sessions (for testing). */
  clear(): void {
    for (const timer of this.timers.values()) {
      clearTimeout(timer);
    }
    this.store.clear();
    this.timers.clear();
  }
}
