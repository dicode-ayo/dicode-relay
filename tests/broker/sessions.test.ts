/**
 * SessionStore unit tests.
 */

import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { SessionStore } from "../../src/broker/sessions.js";
import { testSessionTtlMs } from "../helpers.js";
import type { Session } from "../../src/broker/sessions.js";

function makeSession(sessionId?: string): Session {
  return {
    sessionId: sessionId ?? randomBytes(16).toString("hex"),
    relayUuid: randomBytes(32).toString("hex"),
    pubkey: randomBytes(65),
    pkceChallenge: randomBytes(32).toString("base64url"),
    provider: "github",
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
}

describe("SessionStore", () => {
  it("set and get a session", () => {
    const store = new SessionStore(testSessionTtlMs);
    const session = makeSession("test-session-1");

    store.set(session);
    expect(store.get("test-session-1")).toEqual(session);
    expect(store.size).toBe(1);

    store.clear();
  });

  it("get returns undefined for unknown session ID", () => {
    const store = new SessionStore(testSessionTtlMs);
    expect(store.get("nonexistent")).toBeUndefined();
    store.clear();
  });

  it("delete removes session and cancels timer", () => {
    const store = new SessionStore(testSessionTtlMs);
    const session = makeSession("del-session");
    store.set(session);
    expect(store.size).toBe(1);

    store.delete("del-session");
    expect(store.size).toBe(0);
    expect(store.get("del-session")).toBeUndefined();

    store.clear();
  });

  it("delete on nonexistent session is idempotent", () => {
    const store = new SessionStore(testSessionTtlMs);
    // Should not throw
    store.delete("does-not-exist");
    expect(store.size).toBe(0);
    store.clear();
  });

  it("replacing a session with same ID cancels old timer", () => {
    const store = new SessionStore(testSessionTtlMs);
    const session1 = makeSession("dup-id");
    const session2 = { ...session1, provider: "slack" };

    store.set(session1);
    store.set(session2); // replaces session1

    expect(store.size).toBe(1);
    expect(store.get("dup-id")?.provider).toBe("slack");

    store.clear();
  });

  it("clear removes all sessions", () => {
    const store = new SessionStore(testSessionTtlMs);
    store.set(makeSession("s1"));
    store.set(makeSession("s2"));
    store.set(makeSession("s3"));
    expect(store.size).toBe(3);

    store.clear();
    expect(store.size).toBe(0);
  });

  it("session with optional scope field", () => {
    const store = new SessionStore(testSessionTtlMs);
    const session: Session = {
      ...makeSession("scoped"),
      scope: "repo user",
    };
    store.set(session);
    expect(store.get("scoped")?.scope).toBe("repo user");
    store.clear();
  });

  it("session expires after TTL (5 min)", () => {
    vi.useFakeTimers();
    try {
      const store = new SessionStore(testSessionTtlMs);
      const session = makeSession("ttl-test");

      store.set(session);
      expect(store.size).toBe(1);

      // Advance past 5 min TTL
      vi.advanceTimersByTime(5 * 60 * 1000 + 1000);

      // Session should have been evicted by the timer callback
      expect(store.size).toBe(0);
      expect(store.get("ttl-test")).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});
