# Status Page Design

## Summary

Add a password-protected status dashboard to the relay server that displays
connected clients with per-connection request metrics, global request totals,
and process resource usage (CPU, memory). Server-rendered HTML with inline
auto-refresh — no new dependencies, no frontend build step.

---

## Architecture

### New modules

```
src/status/
  metrics.ts   — MetricsCollector: sliding-window request counters per client + global
  auth.ts      — HTTP Basic Auth middleware gated by STATUS_PASSWORD env var
  page.ts      — server-rendered HTML page builder (returns string)
```

### New routes (Express)

| Route           | Method | Auth     | Response       |
|-----------------|--------|----------|----------------|
| `GET /status`   | GET    | Basic    | HTML dashboard |
| `GET /api/status` | GET | Basic    | JSON snapshot  |

Both routes return 404 if `STATUS_PASSWORD` is not set.

### Wiring

`MetricsCollector` is instantiated once in `index.ts` and:
- Passed to `RelayServer` so it can call `metrics.record(uuid)` on every
  forwarded request and `metrics.registerClient(uuid)` / `metrics.removeClient(uuid)`
  on connect/disconnect.
- Passed to the status route handlers for rendering.

---

## Data Model

### Per-client metrics

```ts
interface ClientMetrics {
  uuid: string;
  connectedAt: number;            // Date.now() at registration
  secondBuckets: Uint32Array;     // 3600 entries (1 hour), circular buffer
  secondIndex: number;            // current write position
  secondEpoch: number;            // unix second of bucket at secondIndex
  hourBuckets: Uint32Array;       // 24 entries (1 day), circular buffer
  hourIndex: number;
  hourEpoch: number;              // unix hour of bucket at hourIndex
  totalRequests: number;
}
```

### Sliding-window mechanics

When `record(uuid)` is called:
1. Compute current unix second and hour.
2. If the current second differs from `secondEpoch`, advance the ring buffer
   (zero out skipped buckets), update `secondIndex` and `secondEpoch`.
3. Increment `secondBuckets[secondIndex]`.
4. Same logic for `hourBuckets` / `hourIndex` / `hourEpoch`.
5. Increment `totalRequests`.

### Derived metrics (computed on read)

| Metric    | Computation                                      |
|-----------|--------------------------------------------------|
| req/sec   | `secondBuckets[secondIndex]` (current second)    |
| req/hour  | sum of all 3600 `secondBuckets` entries           |
| req/day   | sum of all 24 `hourBuckets` entries               |

### Process metrics (collected on-demand)

```ts
interface ProcessMetrics {
  uptimeSeconds: number;          // process.uptime()
  rssBytes: number;               // process.memoryUsage().rss
  heapUsedBytes: number;          // process.memoryUsage().heapUsed
  heapTotalBytes: number;         // process.memoryUsage().heapTotal
  cpuPercent: number;             // derived from process.cpuUsage() delta
}
```

CPU percentage is computed by sampling `process.cpuUsage()` twice with a short
interval (~100ms) and computing `(userDelta + systemDelta) / (elapsed * 1000)`.
Cached for 1 second to avoid excessive sampling.

---

## Authentication

- **Mechanism:** HTTP Basic Auth.
- **Credential:** Username is ignored; password must match `STATUS_PASSWORD` env var.
- **Disabled state:** If `STATUS_PASSWORD` is not set, the `/status` and
  `/api/status` routes return 404 (status page is effectively disabled).
- **No sessions:** The browser caches Basic Auth credentials for the tab lifetime.

---

## HTML Page (`page.ts`)

Server-rendered, self-contained HTML. No external assets or CDN links.

### Layout

1. **Header bar:** "dicode-relay status" + uptime
2. **Process section:** CPU %, RSS, heap used / heap total (formatted as MB)
3. **Global stats row:** total connected clients, global req/sec, req/hour, req/day
4. **Client table:**
   - Columns: UUID (first 12 chars + `...`), connected duration (human-readable),
     req/sec, req/hour, req/day, total requests
   - Sorted by total requests descending
5. **Footer:** auto-refresh indicator

### Styling

- Dark theme, monospace font
- Minimal inline CSS (~50 lines)
- Responsive table with horizontal scroll on narrow screens

### Auto-refresh

Inline `<script>` (~20 lines):
- Fetches `GET /api/status` every 5 seconds
- Updates DOM elements by ID (no full page reload)
- Shows "connection lost" indicator if fetch fails

---

## JSON API (`GET /api/status`)

```json
{
  "uptime": 86400,
  "process": {
    "cpuPercent": 2.3,
    "rssBytes": 52428800,
    "heapUsedBytes": 31457280,
    "heapTotalBytes": 41943040
  },
  "global": {
    "connectedClients": 5,
    "reqPerSec": 12,
    "reqPerHour": 4320,
    "reqPerDay": 98000
  },
  "clients": [
    {
      "uuid": "a1b2c3d4e5f6...",
      "connectedAt": 1712678400000,
      "connectedDuration": "2h 15m",
      "reqPerSec": 3,
      "reqPerHour": 1080,
      "reqPerDay": 24000,
      "totalRequests": 50000
    }
  ]
}
```

---

## Environment variables

| Variable          | Required | Description                                |
|-------------------|----------|--------------------------------------------|
| `STATUS_PASSWORD` | No       | Password for status page. If unset, status page returns 404. |

Add to `.env.example` with comment.

---

## Integration with RelayServer

The `MetricsCollector` needs hooks in `RelayServer`:

1. **On successful handshake** (after storing client in registry):
   `metrics.registerClient(uuid)`
2. **On client disconnect** (when removing from registry):
   `metrics.removeClient(uuid)`
3. **On request forwarded** (in the webhook forwarding handler in `index.ts`):
   `metrics.record(uuid)`

The `RelayServer` class does NOT depend on `MetricsCollector` — the hooks are
called from `index.ts` where both are in scope. This keeps the relay module
clean and the metrics module optional.

**Update:** `RelayServer` needs to emit events or accept callbacks so `index.ts`
can wire in metrics. Options:
- **EventEmitter:** `relayServer.on("client:connected", (uuid) => ...)` — cleanest
- **Callback injection:** pass callbacks in constructor options

Recommend EventEmitter since `RelayServer` may gain other consumers later.

---

## Northstar: Prometheus Migration (Approach B)

When the relay outgrows in-process metrics and needs historical data, alerting,
or multi-instance aggregation, migrate to Prometheus + Grafana.

### Steps

1. **Add `prom-client`** dependency (~50KB, no transitive deps).

2. **Replace `MetricsCollector` internals** with Prometheus primitives:
   - `relay_requests_total` — Counter, labels: `{uuid, method, status}`
   - `relay_request_duration_seconds` — Histogram, labels: `{uuid}`
   - `relay_connected_clients` — Gauge (inc on connect, dec on disconnect)
   - `relay_process_*` — use `prom-client`'s `collectDefaultMetrics()`

3. **Expose `GET /metrics`** endpoint (Prometheus scrape target):
   - Protected by same `STATUS_PASSWORD` Basic Auth or a separate
     `METRICS_PASSWORD` for machine-to-machine auth.
   - Returns `text/plain; version=0.0.4` format.

4. **Prometheus configuration:**
   ```yaml
   scrape_configs:
     - job_name: dicode-relay
       scrape_interval: 15s
       basic_auth:
         username: dicode
         password: <STATUS_PASSWORD>
       static_configs:
         - targets: ["relay.dicode.app:5553"]
   ```

5. **Grafana dashboard** — create a JSON dashboard template covering:
   - Connected clients over time (gauge graph)
   - Request rate by client (stacked area chart)
   - Request latency percentiles (p50, p95, p99)
   - Process CPU and memory (from default metrics)
   - Error rate (5xx responses)

6. **Alerting rules** (Prometheus alertmanager):
   - `RelayNoClients` — 0 connected clients for > 5 min
   - `RelayHighErrorRate` — 5xx rate > 5% for > 2 min
   - `RelayHighMemory` — RSS > 80% of container limit for > 5 min

7. **Keep the HTML status page** as a lightweight fallback that reads from
   the same Prometheus counters, so operators can check status without
   Grafana access.

### Infrastructure requirements

- Prometheus instance (or managed: Grafana Cloud, AWS AMP, etc.)
- Grafana instance for dashboards
- Persistent storage for Prometheus TSDB (~50MB/day for a single relay)

---

## Test plan

### `tests/status/metrics.test.ts`
- `record(uuid)` increments correct second and hour buckets
- Sliding window advances correctly (simulate time progression)
- `removeClient(uuid)` cleans up metrics
- Global aggregation sums across all clients
- Process metrics return valid numbers

### `tests/status/auth.test.ts`
- Valid password → 200
- Wrong password → 401
- No `STATUS_PASSWORD` set → 404
- No `Authorization` header → 401 with `WWW-Authenticate` response header

### `tests/status/page.test.ts`
- HTML response contains expected sections (client table, process metrics)
- JSON API returns correct structure
- Client list sorted by total requests descending

---

## Files changed

| File | Change |
|------|--------|
| `src/status/metrics.ts` | New — MetricsCollector class |
| `src/status/auth.ts` | New — Basic Auth middleware |
| `src/status/page.ts` | New — HTML renderer + JSON builder |
| `src/index.ts` | Wire metrics, add `/status` and `/api/status` routes |
| `src/relay/server.ts` | Add EventEmitter for client:connected / client:disconnected |
| `.env.example` | Add `STATUS_PASSWORD` |
| `tests/status/metrics.test.ts` | New |
| `tests/status/auth.test.ts` | New |
| `tests/status/page.test.ts` | New |
