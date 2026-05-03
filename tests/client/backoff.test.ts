import { describe, expect, it } from "vitest";
import { newBackoff } from "../../src/client/backoff.js";

describe("newBackoff", () => {
  it("starts near 1s and doubles up to 60s", () => {
    const b = newBackoff();
    const expected = [1000, 2000, 4000, 8000, 16000];
    for (const want of expected) {
      const got = b.next();
      expect(got).toBeGreaterThanOrEqual(want * 0.8);
      expect(got).toBeLessThanOrEqual(want * 1.2);
    }
  });
  it("caps at 60s (with up to 20% jitter)", () => {
    const b = newBackoff();
    for (let i = 0; i < 20; i++) b.next();
    const big = b.next();
    expect(big).toBeLessThanOrEqual(72_000);
  });
  it("reset rewinds to ~1s", () => {
    const b = newBackoff();
    for (let i = 0; i < 10; i++) b.next();
    b.reset();
    const after = b.next();
    expect(after).toBeLessThanOrEqual(1200);
  });
});
