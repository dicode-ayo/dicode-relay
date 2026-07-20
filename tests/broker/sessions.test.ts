/**
 * SeenSet unit tests — per-instance single-use guard for OAuth session ids.
 */

import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { SeenSet } from "../../src/broker/sessions.js";
import { testSessionTtlMs } from "../helpers.js";

describe("SeenSet", () => {
  it("add returns true the first time an id is seen", () => {
    const seen = new SeenSet(testSessionTtlMs);
    expect(seen.add("id-1")).toBe(true);
    expect(seen.has("id-1")).toBe(true);
    expect(seen.size).toBe(1);
    seen.clear();
  });

  it("add returns false on a replay of the same id", () => {
    const seen = new SeenSet(testSessionTtlMs);
    expect(seen.add("dup")).toBe(true);
    expect(seen.add("dup")).toBe(false);
    expect(seen.size).toBe(1);
    seen.clear();
  });

  it("has returns false for an unseen id", () => {
    const seen = new SeenSet(testSessionTtlMs);
    expect(seen.has(randomBytes(16).toString("hex"))).toBe(false);
    seen.clear();
  });

  it("clear removes all tracked ids", () => {
    const seen = new SeenSet(testSessionTtlMs);
    seen.add("a");
    seen.add("b");
    expect(seen.size).toBe(2);
    seen.clear();
    expect(seen.size).toBe(0);
    expect(seen.has("a")).toBe(false);
  });

  it("a tracked id expires after the TTL, permitting the id again", () => {
    vi.useFakeTimers();
    try {
      const seen = new SeenSet(testSessionTtlMs);
      expect(seen.add("ttl")).toBe(true);
      expect(seen.size).toBe(1);

      vi.advanceTimersByTime(testSessionTtlMs + 1000);

      expect(seen.size).toBe(0);
      expect(seen.has("ttl")).toBe(false);
      // After expiry the id is treated as fresh again (replay window closed).
      expect(seen.add("ttl")).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
