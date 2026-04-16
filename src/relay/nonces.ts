/**
 * NonceStore — prevents replay attacks by tracking seen nonces for 60 seconds.
 * O(1) lookup and insertion. Entries are evicted after their TTL expires.
 */

interface NonceEntry {
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
}

export class NonceStore {
  private readonly store = new Map<string, NonceEntry>();
  private readonly ttlMs: number;

  /** @param ttlMs defaults live in the Zod config schema (config.ts) */
  constructor(ttlMs = 60_000) {
    this.ttlMs = ttlMs;
  }

  /**
   * Returns true if the nonce has been seen within the TTL window.
   * Registers the nonce so future calls return true.
   */
  check(nonce: string): boolean {
    if (this.store.has(nonce)) {
      return true;
    }
    const timer = setTimeout(() => {
      this.store.delete(nonce);
    }, this.ttlMs);
    // Allow Node.js to exit even if the timer is still pending
    timer.unref();

    this.store.set(nonce, { expiresAt: Date.now() + this.ttlMs, timer });
    return false;
  }

  /** Number of nonces currently tracked (for testing / observability). */
  get size(): number {
    return this.store.size;
  }

  /** Clear all stored nonces (for testing). */
  clear(): void {
    for (const entry of this.store.values()) {
      clearTimeout(entry.timer);
    }
    this.store.clear();
  }
}
