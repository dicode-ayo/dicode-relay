# Status Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a password-protected status dashboard showing connected clients with per-connection request metrics and process resource usage.

**Architecture:** Three new modules under `src/status/` — `metrics.ts` (sliding-window counters), `auth.ts` (Basic Auth middleware), `page.ts` (HTML renderer + JSON builder). `RelayServer` gains an EventEmitter for client lifecycle events. `index.ts` wires metrics hooks and mounts the status routes.

**Tech Stack:** Express middleware, `node:crypto` (none new), `process.memoryUsage()` / `process.cpuUsage()` for resource metrics. No new dependencies.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `src/status/metrics.ts` | Create | `MetricsCollector` class — per-client sliding-window ring buffers, global aggregation, process stats |
| `src/status/auth.ts` | Create | `statusAuth()` Express middleware — HTTP Basic Auth against `STATUS_PASSWORD` env var |
| `src/status/page.ts` | Create | `renderStatusPage()` returns HTML string; `buildStatusJson()` returns JSON payload |
| `src/relay/server.ts` | Modify | Add EventEmitter: emit `client:connected` and `client:disconnected` events |
| `src/index.ts` | Modify | Instantiate `MetricsCollector`, wire events, mount `/status` and `/api/status` routes, hook `record()` into forwarding |
| `.env.example` | Modify | Add `STATUS_PASSWORD` |
| `tests/status/metrics.test.ts` | Create | Sliding window logic, per-client tracking, process metrics |
| `tests/status/auth.test.ts` | Create | Basic Auth middleware behavior |
| `tests/status/page.test.ts` | Create | HTML rendering and JSON API structure |

---

### Task 1: Add EventEmitter to RelayServer

**Files:**
- Modify: `src/relay/server.ts`
- Create: `tests/relay/events.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/relay/events.test.ts`:

```ts
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { RelayServer } from "../../src/relay/server.js";

function generateSigningIdentity(): {
  uuid: string;
  pubkeyBase64: string;
  sign: (message: Buffer) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const spki = publicKey as Buffer;
  const pubkeyBytes = spki.subarray(spki.length - 65);
  const uuid = createHash("sha256").update(pubkeyBytes).digest("hex");
  const sign = (message: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(message);
    return signer.sign(privateKey, "base64");
  };
  return { uuid, pubkeyBase64: pubkeyBytes.toString("base64"), sign };
}

function performHandshake(
  ws: WebSocket,
  identity: ReturnType<typeof generateSigningIdentity>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString("utf8")) as {
        type: string;
        nonce?: string;
      };
      if (msg.type === "challenge" && msg.nonce !== undefined) {
        const nonceBytes = Buffer.from(msg.nonce, "hex");
        const timestamp = Math.floor(Date.now() / 1000);
        const tsBytes = Buffer.allocUnsafe(8);
        tsBytes.writeBigUInt64BE(BigInt(timestamp));
        const sigMessage = Buffer.concat([nonceBytes, tsBytes]);
        ws.send(
          JSON.stringify({
            type: "hello",
            uuid: identity.uuid,
            pubkey: identity.pubkeyBase64,
            sig: identity.sign(sigMessage),
            timestamp,
          }),
        );
      } else if (msg.type === "welcome") {
        resolve();
      } else if (msg.type === "error") {
        reject(new Error("handshake failed"));
      }
    });
  });
}

describe("RelayServer events", () => {
  let server: RelayServer;

  beforeEach(() => {
    server = new RelayServer({ baseUrl: "ws://localhost", port: 0 });
  });

  afterEach(async () => {
    await server.close();
  });

  it("emits client:connected on successful handshake", async () => {
    const identity = generateSigningIdentity();
    const connected = new Promise<string>((resolve) => {
      server.on("client:connected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const ws = new WebSocket(`ws://localhost:${server.port.toString()}`);
    await performHandshake(ws, identity);

    const uuid = await connected;
    expect(uuid).toBe(identity.uuid);
    ws.close();
  });

  it("emits client:disconnected when client closes connection", async () => {
    const identity = generateSigningIdentity();
    const disconnected = new Promise<string>((resolve) => {
      server.on("client:disconnected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const ws = new WebSocket(`ws://localhost:${server.port.toString()}`);
    await performHandshake(ws, identity);
    ws.close();

    const uuid = await disconnected;
    expect(uuid).toBe(identity.uuid);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/relay/events.test.ts`
Expected: FAIL — `server.on` is not a function (RelayServer is not an EventEmitter)

- [ ] **Step 3: Make RelayServer extend EventEmitter**

In `src/relay/server.ts`, add the import and extend:

```ts
// Add to imports at top of file:
import { EventEmitter } from "node:events";

// Change class declaration:
export class RelayServer extends EventEmitter {
```

Add `super()` as the first line of the constructor:

```ts
constructor(opts: RelayServerOptions) {
  super();
  this.baseUrl = opts.baseUrl;
  // ... rest stays the same
```

After the welcome message send (after `this.sendMessage(ws, welcome);` around line 279), add:

```ts
this.emit("client:connected", hello.uuid);
```

In the `cleanup` function, before `this.clients.delete(registeredUuid)` (around line 240), add:

```ts
this.emit("client:disconnected", registeredUuid);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/relay/events.test.ts`
Expected: PASS

- [ ] **Step 5: Run full test suite to ensure no regressions**

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 6: Commit**

```
git add src/relay/server.ts tests/relay/events.test.ts
git commit -m "feat(relay): add EventEmitter for client lifecycle events"
```

---

### Task 2: MetricsCollector — core class with sliding-window ring buffers

**Files:**
- Create: `src/status/metrics.ts`
- Create: `tests/status/metrics.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/status/metrics.test.ts`:

```ts
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
      expect(snapshot.process.uptimeSeconds).toBeGreaterThan(0);
      expect(snapshot.process.rssBytes).toBeGreaterThan(0);
      expect(snapshot.process.heapUsedBytes).toBeGreaterThan(0);
      expect(snapshot.process.heapTotalBytes).toBeGreaterThanOrEqual(
        snapshot.process.heapUsedBytes,
      );
      expect(snapshot.process.cpuPercent).toBeGreaterThanOrEqual(0);
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/status/metrics.test.ts`
Expected: FAIL — cannot resolve `../../src/status/metrics.js`

- [ ] **Step 3: Implement MetricsCollector**

Create `src/status/metrics.ts`:

```ts
const SECONDS_PER_HOUR = 3600;
const HOURS_PER_DAY = 24;

interface ClientMetricsEntry {
  uuid: string;
  connectedAt: number;
  secondBuckets: Uint32Array;
  secondIndex: number;
  secondEpoch: number;
  hourBuckets: Uint32Array;
  hourIndex: number;
  hourEpoch: number;
  totalRequests: number;
}

export interface ClientSnapshot {
  uuid: string;
  connectedAt: number;
  connectedDuration: string;
  reqPerSec: number;
  reqPerHour: number;
  reqPerDay: number;
  totalRequests: number;
}

export interface ProcessSnapshot {
  uptimeSeconds: number;
  rssBytes: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  cpuPercent: number;
}

export interface StatusSnapshot {
  global: {
    connectedClients: number;
    reqPerSec: number;
    reqPerHour: number;
    reqPerDay: number;
  };
  process: ProcessSnapshot;
  clients: ClientSnapshot[];
}

export class MetricsCollector {
  private readonly entries = new Map<string, ClientMetricsEntry>();
  private lastCpuUsage = process.cpuUsage();
  private lastCpuTime = Date.now();
  private cachedCpuPercent = 0;

  registerClient(uuid: string): void {
    const nowSec = Math.floor(Date.now() / 1000);
    const nowHour = Math.floor(nowSec / 3600);
    this.entries.set(uuid, {
      uuid,
      connectedAt: Date.now(),
      secondBuckets: new Uint32Array(SECONDS_PER_HOUR),
      secondIndex: 0,
      secondEpoch: nowSec,
      hourBuckets: new Uint32Array(HOURS_PER_DAY),
      hourIndex: 0,
      hourEpoch: nowHour,
      totalRequests: 0,
    });
  }

  removeClient(uuid: string): void {
    this.entries.delete(uuid);
  }

  record(uuid: string): void {
    const entry = this.entries.get(uuid);
    if (entry === undefined) return;

    const nowSec = Math.floor(Date.now() / 1000);
    const nowHour = Math.floor(nowSec / 3600);

    this.advanceSecondBuckets(entry, nowSec);
    this.advanceHourBuckets(entry, nowHour);

    entry.secondBuckets[entry.secondIndex]!++;
    entry.hourBuckets[entry.hourIndex]!++;
    entry.totalRequests++;
  }

  snapshot(): StatusSnapshot {
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const nowHour = Math.floor(nowSec / 3600);
    const clients: ClientSnapshot[] = [];

    let globalReqPerSec = 0;
    let globalReqPerHour = 0;
    let globalReqPerDay = 0;

    for (const entry of this.entries.values()) {
      this.advanceSecondBuckets(entry, nowSec);
      this.advanceHourBuckets(entry, nowHour);

      const reqPerSec = entry.secondBuckets[entry.secondIndex] ?? 0;
      const reqPerHour = sumUint32Array(entry.secondBuckets);
      const reqPerDay = sumUint32Array(entry.hourBuckets);

      globalReqPerSec += reqPerSec;
      globalReqPerHour += reqPerHour;
      globalReqPerDay += reqPerDay;

      clients.push({
        uuid: entry.uuid,
        connectedAt: entry.connectedAt,
        connectedDuration: formatDuration(now - entry.connectedAt),
        reqPerSec,
        reqPerHour,
        reqPerDay,
        totalRequests: entry.totalRequests,
      });
    }

    clients.sort((a, b) => b.totalRequests - a.totalRequests);

    return {
      global: {
        connectedClients: this.entries.size,
        reqPerSec: globalReqPerSec,
        reqPerHour: globalReqPerHour,
        reqPerDay: globalReqPerDay,
      },
      process: this.processSnapshot(),
      clients,
    };
  }

  private advanceSecondBuckets(entry: ClientMetricsEntry, nowSec: number): void {
    const elapsed = nowSec - entry.secondEpoch;
    if (elapsed <= 0) return;

    const toZero = Math.min(elapsed, SECONDS_PER_HOUR);
    for (let i = 1; i <= toZero; i++) {
      const idx = (entry.secondIndex + i) % SECONDS_PER_HOUR;
      entry.secondBuckets[idx] = 0;
    }
    entry.secondIndex = (entry.secondIndex + elapsed) % SECONDS_PER_HOUR;
    entry.secondEpoch = nowSec;
  }

  private advanceHourBuckets(entry: ClientMetricsEntry, nowHour: number): void {
    const elapsed = nowHour - entry.hourEpoch;
    if (elapsed <= 0) return;

    const toZero = Math.min(elapsed, HOURS_PER_DAY);
    for (let i = 1; i <= toZero; i++) {
      const idx = (entry.hourIndex + i) % HOURS_PER_DAY;
      entry.hourBuckets[idx] = 0;
    }
    entry.hourIndex = (entry.hourIndex + elapsed) % HOURS_PER_DAY;
    entry.hourEpoch = nowHour;
  }

  private processSnapshot(): ProcessSnapshot {
    const now = Date.now();
    const elapsedMs = now - this.lastCpuTime;

    if (elapsedMs >= 1000) {
      const currentCpu = process.cpuUsage(this.lastCpuUsage);
      const totalCpuUs = currentCpu.user + currentCpu.system;
      this.cachedCpuPercent = (totalCpuUs / (elapsedMs * 1000)) * 100;
      this.lastCpuUsage = process.cpuUsage();
      this.lastCpuTime = now;
    }

    const mem = process.memoryUsage();
    return {
      uptimeSeconds: Math.floor(process.uptime()),
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      cpuPercent: Math.round(this.cachedCpuPercent * 100) / 100,
    };
  }
}

function sumUint32Array(arr: Uint32Array): number {
  let sum = 0;
  for (let i = 0; i < arr.length; i++) {
    sum += arr[i] ?? 0;
  }
  return sum;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return `${days.toString()}d ${hours.toString()}h ${minutes.toString()}m`;
  if (hours > 0) return `${hours.toString()}h ${minutes.toString()}m`;
  if (minutes > 0) return `${minutes.toString()}m ${seconds.toString()}s`;
  return `${seconds.toString()}s`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/status/metrics.test.ts`
Expected: PASS (all 10 tests)

- [ ] **Step 5: Commit**

```
git add src/status/metrics.ts tests/status/metrics.test.ts
git commit -m "feat(status): add MetricsCollector with sliding-window ring buffers"
```

---

### Task 3: Basic Auth middleware

**Files:**
- Create: `src/status/auth.ts`
- Create: `tests/status/auth.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/status/auth.test.ts`:

```ts
import { describe, expect, it, afterEach } from "vitest";
import express from "express";
import { createServer, type Server } from "node:http";
import { statusAuth } from "../../src/status/auth.js";

function startApp(password: string | undefined): Promise<{ port: number; server: Server }> {
  const app = express();
  app.use(statusAuth(password));
  app.get("/test", (_req, res) => {
    res.json({ ok: true });
  });
  const server = createServer(app);
  return new Promise((resolve) => {
    server.listen(0, () => {
      const addr = server.address();
      if (typeof addr === "object" && addr !== null) {
        resolve({ port: addr.port, server });
      }
    });
  });
}

function basicAuthHeader(password: string): string {
  return "Basic " + Buffer.from(":" + password).toString("base64");
}

describe("statusAuth middleware", () => {
  let server: Server | null = null;

  afterEach(() => {
    if (server !== null) {
      server.close();
      server = null;
    }
  });

  it("returns 404 when STATUS_PASSWORD is undefined", async () => {
    const { port, server: s } = await startApp(undefined);
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`);
    expect(res.status).toBe(404);
  });

  it("returns 401 with WWW-Authenticate when no auth header sent", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Basic realm="dicode-relay status"');
  });

  it("returns 401 for wrong password", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("wrongpassword") },
    });
    expect(res.status).toBe(401);
  });

  it("returns 200 for correct password", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("secret123") },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/status/auth.test.ts`
Expected: FAIL — cannot resolve `../../src/status/auth.js`

- [ ] **Step 3: Implement statusAuth middleware**

Create `src/status/auth.ts`:

```ts
import type { RequestHandler } from "express";

export function statusAuth(password: string | undefined): RequestHandler {
  return (req, res, next) => {
    if (password === undefined) {
      res.status(404).json({ error: "status page not configured" });
      return;
    }

    const authHeader = req.headers.authorization;
    if (authHeader === undefined) {
      res.setHeader("WWW-Authenticate", 'Basic realm="dicode-relay status"');
      res.status(401).json({ error: "authentication required" });
      return;
    }

    const match = /^Basic\s+(.+)$/i.exec(authHeader);
    if (match === null || match[1] === undefined) {
      res.status(401).json({ error: "invalid auth format" });
      return;
    }

    const decoded = Buffer.from(match[1], "base64").toString("utf8");
    const colonIndex = decoded.indexOf(":");
    const providedPassword = colonIndex === -1 ? decoded : decoded.substring(colonIndex + 1);

    if (providedPassword !== password) {
      res.status(401).json({ error: "invalid credentials" });
      return;
    }

    next();
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/status/auth.test.ts`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

```
git add src/status/auth.ts tests/status/auth.test.ts
git commit -m "feat(status): add HTTP Basic Auth middleware for status page"
```

---

### Task 4: HTML page renderer + JSON builder

**Files:**
- Create: `src/status/page.ts`
- Create: `tests/status/page.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/status/page.test.ts`:

```ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/status/page.test.ts`
Expected: FAIL — cannot resolve `../../src/status/page.js`

- [ ] **Step 3: Implement page.ts**

Create `src/status/page.ts`:

```ts
import type { StatusSnapshot } from "./metrics.js";

export function buildStatusJson(snapshot: StatusSnapshot): StatusSnapshot {
  return snapshot;
}

export function renderStatusPage(snapshot: StatusSnapshot): string {
  const { global, process: proc, clients } = snapshot;
  const rssM = (proc.rssBytes / 1_048_576).toFixed(1);
  const heapUsedM = (proc.heapUsedBytes / 1_048_576).toFixed(1);
  const heapTotalM = (proc.heapTotalBytes / 1_048_576).toFixed(1);

  const clientRows =
    clients.length === 0
      ? `<tr><td colspan="6" style="text-align:center;color:#888">No clients connected</td></tr>`
      : clients
          .map(
            (c) => `<tr>
          <td title="${esc(c.uuid)}">${esc(c.uuid.substring(0, 12))}...</td>
          <td>${esc(c.connectedDuration)}</td>
          <td>${c.reqPerSec.toString()}</td>
          <td>${c.reqPerHour.toString()}</td>
          <td>${c.reqPerDay.toString()}</td>
          <td>${c.totalRequests.toString()}</td>
        </tr>`,
          )
          .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dicode-relay status</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: "SF Mono", "Fira Code", monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }
  h1 { font-size: 1.4rem; color: #58a6ff; margin-bottom: 8px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .section { margin-bottom: 24px; }
  .section h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 8px; border-bottom: 1px solid #21262d; padding-bottom: 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 12px; }
  .card .label { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }
  .card .value { font-size: 1.3rem; color: #f0f6fc; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #21262d; border-radius: 6px; overflow: hidden; }
  th { text-align: left; padding: 8px 12px; background: #21262d; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }
  td { padding: 8px 12px; border-top: 1px solid #21262d; font-size: 0.85rem; }
  tr:hover td { background: #1c2128; }
  .refresh-indicator { color: #8b949e; font-size: 0.75rem; margin-top: 16px; }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr 1fr; } table { display: block; overflow-x: auto; } }
</style>
</head>
<body>
  <h1>dicode-relay status</h1>
  <div class="meta">Uptime: ${formatUptime(proc.uptimeSeconds)}</div>

  <div class="section">
    <h2>Process</h2>
    <div class="grid">
      <div class="card"><div class="label">CPU</div><div class="value" id="cpu">${proc.cpuPercent.toString()}%</div></div>
      <div class="card"><div class="label">RSS</div><div class="value" id="rss">${rssM} MB</div></div>
      <div class="card"><div class="label">Heap</div><div class="value" id="heap">${heapUsedM} / ${heapTotalM} MB</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Global</h2>
    <div class="grid">
      <div class="card"><div class="label">Connected</div><div class="value" id="g-clients">${global.connectedClients.toString()}</div></div>
      <div class="card"><div class="label">Req/sec</div><div class="value" id="g-rps">${global.reqPerSec.toString()}</div></div>
      <div class="card"><div class="label">Req/hour</div><div class="value" id="g-rph">${global.reqPerHour.toString()}</div></div>
      <div class="card"><div class="label">Req/day</div><div class="value" id="g-rpd">${global.reqPerDay.toString()}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Clients</h2>
    <table>
      <thead>
        <tr><th>UUID</th><th>Connected</th><th>Req/s</th><th>Req/h</th><th>Req/d</th><th>Total</th></tr>
      </thead>
      <tbody id="client-table">
        ${clientRows}
      </tbody>
    </table>
  </div>

  <div class="refresh-indicator" id="refresh-status">Auto-refreshing every 5s</div>

  <script>
    async function refresh() {
      try {
        const res = await fetch("/api/status", { credentials: "same-origin" });
        if (!res.ok) return;
        const d = await res.json();
        const p = d.process;
        document.getElementById("cpu").textContent = p.cpuPercent + "%";
        document.getElementById("rss").textContent = (p.rssBytes / 1048576).toFixed(1) + " MB";
        document.getElementById("heap").textContent = (p.heapUsedBytes / 1048576).toFixed(1) + " / " + (p.heapTotalBytes / 1048576).toFixed(1) + " MB";
        document.getElementById("g-clients").textContent = d.global.connectedClients;
        document.getElementById("g-rps").textContent = d.global.reqPerSec;
        document.getElementById("g-rph").textContent = d.global.reqPerHour;
        document.getElementById("g-rpd").textContent = d.global.reqPerDay;
        const tbody = document.getElementById("client-table");
        if (d.clients.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#888">No clients connected</td></tr>';
        } else {
          tbody.innerHTML = d.clients.map(function(c) {
            return '<tr><td title="' + c.uuid + '">' + c.uuid.substring(0, 12) + '...</td><td>' + c.connectedDuration + '</td><td>' + c.reqPerSec + '</td><td>' + c.reqPerHour + '</td><td>' + c.reqPerDay + '</td><td>' + c.totalRequests + '</td></tr>';
          }).join("");
        }
        document.getElementById("refresh-status").textContent = "Auto-refreshing every 5s";
      } catch {
        document.getElementById("refresh-status").textContent = "Connection lost - retrying...";
      }
    }
    setInterval(refresh, 5000);
  </script>
</body>
</html>`;
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d > 0) return `${d.toString()}d ${h.toString()}h ${m.toString()}m`;
  if (h > 0) return `${h.toString()}h ${m.toString()}m ${s.toString()}s`;
  return `${m.toString()}m ${s.toString()}s`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/status/page.test.ts`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```
git add src/status/page.ts tests/status/page.test.ts
git commit -m "feat(status): add server-rendered HTML page and JSON builder"
```

---

### Task 5: Wire everything into index.ts and update .env.example

**Files:**
- Modify: `src/index.ts`
- Modify: `.env.example`

- [ ] **Step 1: Update .env.example**

Add after the `TLS_KEY_FILE=` line:

```sh

# ---------------------------------------------------------------------------
# Status page (optional - disabled if not set)
# ---------------------------------------------------------------------------

# Password for the /status dashboard (HTTP Basic Auth)
STATUS_PASSWORD=
```

- [ ] **Step 2: Add imports to index.ts**

Add these imports after the existing imports at the top of `src/index.ts`:

```ts
import { MetricsCollector } from "./status/metrics.js";
import { statusAuth } from "./status/auth.js";
import { renderStatusPage, buildStatusJson } from "./status/page.js";
```

- [ ] **Step 3: Instantiate metrics and wire relay events**

After line 48 (`const relayServer = new RelayServer(...)`) add:

```ts
// Metrics collector
const metrics = new MetricsCollector();
const STATUS_PASSWORD = process.env.STATUS_PASSWORD;

// Wire relay lifecycle events to metrics
relayServer.on("client:connected", (uuid: string) => {
  metrics.registerClient(uuid);
});
relayServer.on("client:disconnected", (uuid: string) => {
  metrics.removeClient(uuid);
});
```

- [ ] **Step 4: Add status routes**

Before the health check route (before `app.get("/health", ...)`), add:

```ts
// Status dashboard (password-protected)
app.get("/status", statusAuth(STATUS_PASSWORD), (_req, res) => {
  res.type("html").send(renderStatusPage(metrics.snapshot()));
});

app.get("/api/status", statusAuth(STATUS_PASSWORD), (_req, res) => {
  res.json(buildStatusJson(metrics.snapshot()));
});
```

- [ ] **Step 5: Add metrics recording to webhook forwarding**

In the webhook forwarding handler, add `metrics.record(uuid);` right before the `relayServer.forward(...)` call (before line 80). The forwarding section should look like:

```ts
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

  metrics.record(uuid);

  relayServer
    .forward(uuid, req.method, hookPath, headers, body)
```

- [ ] **Step 6: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 7: Run full test suite**

Run: `npx vitest run`
Expected: All tests pass

- [ ] **Step 8: Commit**

```
git add src/index.ts .env.example
git commit -m "feat(status): wire metrics, auth, and status routes into server"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run full test suite with coverage**

Run: `npx vitest run --coverage`
Expected: All tests pass, coverage meets thresholds

- [ ] **Step 2: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 3: Run linter**

Run: `npx eslint src tests`
Expected: No errors (fix any that appear)

- [ ] **Step 4: Run formatter check**

Run: `npx prettier --check src tests`
Expected: No formatting issues (fix any with `npx prettier --write src tests`)

- [ ] **Step 5: Run build**

Run: `npm run build`
Expected: Compiles successfully to `dist/`
