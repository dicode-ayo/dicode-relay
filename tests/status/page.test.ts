import { describe, expect, it } from "vitest";
import { renderStatusPage, buildStatusJson } from "../../src/status/page.js";
import type { StatusSnapshot } from "../../src/status/metrics.js";

function makeSnapshot(overrides?: Partial<StatusSnapshot>): StatusSnapshot {
  return {
    global: {
      connectedClients: 2,
      reqPerSec: 10,
      reqPerHour: 3600,
      reqPerDay: 86400,
    },
    process: {
      uptimeSeconds: 7200,
      rssBytes: 52_428_800,
      heapUsedBytes: 31_457_280,
      heapTotalBytes: 41_943_040,
      cpuPercent: 2.5,
    },
    clients: [
      {
        uuid: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        connectedAt: Date.now() - 3_600_000,
        connectedDuration: "1h 0m",
        reqPerSec: 7,
        reqPerHour: 2500,
        reqPerDay: 60000,
        totalRequests: 150000,
      },
      {
        uuid: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
        connectedAt: Date.now() - 1_800_000,
        connectedDuration: "30m 0s",
        reqPerSec: 3,
        reqPerHour: 1100,
        reqPerDay: 26400,
        totalRequests: 50000,
      },
    ],
    ...overrides,
  };
}

describe("renderStatusPage", () => {
  it("returns valid HTML with expected sections", () => {
    const html = renderStatusPage(makeSnapshot());
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("dicode-relay status");
    expect(html).toContain("2.5%");
    expect(html).toContain("50.0");
    expect(html).toContain("a1b2c3d4e5f6");
    expect(html).toContain("150000");
  });

  it("handles zero clients", () => {
    const html = renderStatusPage(
      makeSnapshot({
        clients: [],
        global: { connectedClients: 0, reqPerSec: 0, reqPerHour: 0, reqPerDay: 0 },
      }),
    );
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("No clients connected");
  });
});

describe("buildStatusJson", () => {
  it("returns the snapshot as-is", () => {
    const snapshot = makeSnapshot();
    const json = buildStatusJson(snapshot);
    expect(json).toEqual(snapshot);
  });
});
