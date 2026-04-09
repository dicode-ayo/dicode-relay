import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MetricsCollector } from "../../src/status/metrics.js";

describe("MetricsCollector", () => {
  let metrics: MetricsCollector;

  beforeEach(() => {
    metrics = new MetricsCollector();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("client registration", () => {
    it("tracks registered clients", () => {
      metrics.registerClient("abc123");
      const snapshot = metrics.snapshot();
      expect(snapshot.clients).toHaveLength(1);
      expect(snapshot.clients[0]?.uuid).toBe("abc123");
    });

    it("removes client on unregister", () => {
      metrics.registerClient("abc123");
      metrics.removeClient("abc123");
      const snapshot = metrics.snapshot();
      expect(snapshot.clients).toHaveLength(0);
    });

    it("records connectedAt timestamp", () => {
      const before = Date.now();
      metrics.registerClient("abc123");
      const after = Date.now();
      const client = metrics.snapshot().clients[0];
      expect(client?.connectedAt).toBeGreaterThanOrEqual(before);
      expect(client?.connectedAt).toBeLessThanOrEqual(after);
    });
  });

  describe("request recording", () => {
    it("increments totalRequests for a client", () => {
      metrics.registerClient("abc123");
      metrics.record("abc123");
      metrics.record("abc123");
      metrics.record("abc123");
      const client = metrics.snapshot().clients[0];
      expect(client?.totalRequests).toBe(3);
    });

    it("ignores record calls for unknown clients", () => {
      metrics.record("unknown");
      expect(metrics.snapshot().clients).toHaveLength(0);
    });

    it("computes reqPerSec from current second bucket", () => {
      metrics.registerClient("abc123");
      metrics.record("abc123");
      metrics.record("abc123");
      const client = metrics.snapshot().clients[0];
      expect(client?.reqPerSec).toBe(2);
    });
  });

  describe("sliding window advancement", () => {
    it("advances second buckets when time moves forward", () => {
      vi.useFakeTimers();
      const start = new Date("2026-01-01T00:00:00Z");
      vi.setSystemTime(start);

      metrics.registerClient("abc123");
      metrics.record("abc123");

      vi.setSystemTime(new Date(start.getTime() + 1000));
      metrics.record("abc123");

      const client = metrics.snapshot().clients[0];
      expect(client?.reqPerSec).toBe(1);
      expect(client?.totalRequests).toBe(2);
    });

    it("zeroes skipped second buckets", () => {
      vi.useFakeTimers();
      const start = new Date("2026-01-01T00:00:00Z");
      vi.setSystemTime(start);

      metrics.registerClient("abc123");
      metrics.record("abc123");
      metrics.record("abc123");

      vi.setSystemTime(new Date(start.getTime() + 5000));
      metrics.record("abc123");

      const client = metrics.snapshot().clients[0];
      expect(client?.reqPerSec).toBe(1);
      expect(client?.totalRequests).toBe(3);
    });

    it("advances hour buckets when time crosses hour boundary", () => {
      vi.useFakeTimers();
      const start = new Date("2026-01-01T00:00:00Z");
      vi.setSystemTime(start);

      metrics.registerClient("abc123");
      metrics.record("abc123");

      vi.setSystemTime(new Date(start.getTime() + 3600 * 1000));
      metrics.record("abc123");

      const client = metrics.snapshot().clients[0];
      expect(client?.reqPerDay).toBe(2);
      expect(client?.totalRequests).toBe(2);
    });
  });

  describe("global aggregation", () => {
    it("sums metrics across all clients", () => {
      metrics.registerClient("a");
      metrics.registerClient("b");
      metrics.record("a");
      metrics.record("a");
      metrics.record("b");

      const snapshot = metrics.snapshot();
      expect(snapshot.global.connectedClients).toBe(2);
      expect(snapshot.global.reqPerSec).toBe(3);
    });
  });

  describe("process metrics", () => {
    it("returns valid process stats", () => {
      const snapshot = metrics.snapshot();
      expect(snapshot.process.uptimeSeconds).toBeGreaterThanOrEqual(0);
      expect(snapshot.process.rssBytes).toBeGreaterThan(0);
      expect(snapshot.process.heapUsedBytes).toBeGreaterThan(0);
      expect(snapshot.process.heapTotalBytes).toBeGreaterThanOrEqual(
        snapshot.process.heapUsedBytes,
      );
      expect(snapshot.process.cpuPercent).toBeGreaterThanOrEqual(0);
    });
  });
});
