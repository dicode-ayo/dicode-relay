# Scaling & Future Architecture

This document describes the current scalability profile of dicode-relay
and outlines upgrade paths for when the single-process architecture is
outgrown.

---

## Current architecture (single process)

dicode-relay runs as a single Node.js process. All state is held in-memory:

| State | Data structure | Purpose |
|---|---|---|
| `clients` | `Map<uuid, ConnectedClient>` | Daemon WebSocket registry |
| `pending` | `Map<id, PendingRequest>` | In-flight request/response correlation |
| `SessionStore` | `Map<sessionId, Session>` | OAuth broker sessions (5 min TTL) |
| `NonceStore` | `Map<nonce, {expiresAt, timer}>` | Replay prevention (60 s TTL) |
| Metrics | Per-client rolling buckets | Optional status page data |

### Per-connection memory footprint

| Component | Estimate |
|---|---|
| WebSocket object + internal buffers | 2–4 KB |
| ConnectedClient entry (uuid string, pubkey 65 bytes) | ~150 bytes |
| Metrics rolling buckets (if status page enabled) | ~376 bytes |
| V8 overhead (closures, GC metadata) | 1–2 KB |
| **Total per idle connection** | **~4–7 KB** |

Each pending request adds ~100 bytes (promise handlers + timer) plus the
JSON-serialized request/response body in memory until resolved.

---

## Vertical scaling

Vertical scaling (bigger machine, more RAM) works well with one exception:

| Resource | How it scales | Practical limit |
|---|---|---|
| RAM | Linear — more memory = more connections | V8 heap defaults to ~4 GB; adjustable via `--max-old-space-size` up to ~16 GB, but GC pauses grow with heap size |
| CPU cores | **Single-threaded** — only 1 core used | Event loop saturation under heavy crypto (ECDSA verify, ECIES encrypt) or high message throughput |
| Network bandwidth | Linear | No bottleneck in application code |
| File descriptors | Linear — raise `ulimit -n` | OS-level, trivial to configure |

### Estimated capacity by hardware

| Hardware | Idle connections | Active connections (moderate traffic) |
|---|---|---|
| Raspberry Pi 4/5 (8 GB) | 100K–200K | 10K–30K |
| 4-core VPS (16 GB) | 300K–500K | 30K–80K |
| 8-core dedicated (64 GB) | 500K–1M | 50K–150K |

> These assume a single Node.js process with raised file descriptor limits.
> "Active" means regular request forwarding traffic, not just idle WebSocket
> keepalive pings.

### Bottlenecks at scale

1. **GC pauses** — V8 garbage collection can cause 50–100 ms pauses when the
   heap holds hundreds of thousands of Map entries.
2. **Crypto CPU cost** — ECDSA P-256 verification + ECDH + AES-256-GCM takes
   ~1–2 ms per operation on ARM (RPi), ~0.3 ms on x86. Burst onboarding of
   thousands of daemons will queue up on the single thread.
3. **Timer pressure** — 30 s ping interval × N clients = N/30 timer fires per
   second. Node.js handles this efficiently but it adds CPU overhead.

---

## Horizontal scaling

The current design does **not** support running multiple instances
out of the box. The reason is simple: all routing state is in-process.

```
HTTP request → relay instance → lookup uuid in local Map → forward via local WebSocket
```

If a daemon's WebSocket is connected to instance A but an HTTP request arrives
at instance B, the request cannot be forwarded.

### What breaks with multiple instances

| State | Problem |
|---|---|
| `clients` Map | Daemon connects to instance A; HTTP request hits instance B — UUID not found, forward fails |
| `pending` Map | Request/response correlation is local to the instance holding the WebSocket |
| `SessionStore` | OAuth session created on instance A; callback hits instance B — session not found |
| `NonceStore` | Nonce checked only on the local instance — replay possible across instances |
| Metrics | Each instance has a partial view |

---

## Scaling upgrade paths

### Tier 1: Reverse proxy with consistent hash routing (recommended first step)

Place a reverse proxy in front of N relay worker processes. The proxy
inspects the daemon UUID in the request path and routes deterministically
so that the same UUID always reaches the same worker.

```
                          ┌─────────────────┐
   Daemons ──── WSS ────▶│                  │───▶ Worker 1 (port 3001)
                          │   nginx/HAProxy  │───▶ Worker 2 (port 3002)
   HTTP requests ────────▶│   (stateless)    │───▶ Worker 3 (port 3003)
                          │                  │───▶ Worker 4 (port 3004)
                          └─────────────────┘
```

This works because the daemon UUID is already embedded in every request path:

- WebSocket connect: `wss://relay/ws/{uuid}`
- HTTP forward: `POST /relay/{uuid}/...`

The proxy hashes the UUID and routes to the correct backend. No shared state
is required — each worker owns its subset of daemons.

#### nginx example

```nginx
upstream relay_workers {
    hash $uri consistent;

    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    server 127.0.0.1:3003;
    server 127.0.0.1:3004;
}

server {
    listen 443 ssl;
    server_name relay.dicode.app;

    location / {
        proxy_pass http://relay_workers;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
    }
}
```

#### HAProxy example

```
backend relay_workers
    balance uri
    hash-type consistent
    server w1 127.0.0.1:3001 check
    server w2 127.0.0.1:3002 check
    server w3 127.0.0.1:3003 check
    server w4 127.0.0.1:3004 check
```

#### OAuth route handling

OAuth endpoints (`/oauth/start`, `/oauth/callback`) do not include a daemon
UUID in the path. Two options:

- **Simple**: Route all `/oauth/*` traffic to a dedicated worker (e.g., worker 1).
- **Clean**: Move `SessionStore` to Redis. The store is already a Map with TTLs — Redis with key expiry is a natural fit (~20 lines of change).

#### Code changes required

Minimal — the relay code does not need architectural changes:

1. Make the listen port configurable (already supported via `relay.yaml`).
2. Run N instances with different ports.
3. Configure nginx/HAProxy in front.

#### Expected capacity

On a Raspberry Pi 8 GB with 4 workers behind nginx:

- **40K–80K idle connections** (4× single-process capacity)
- **20K–40K active connections** with moderate traffic
- nginx adds ~2 MB RSS overhead

### Tier 2: Shared state with Redis (multi-machine horizontal scaling)

For true multi-machine horizontal scaling, extract in-process state to Redis:

| Component | Redis replacement |
|---|---|
| `clients` Map | Redis hash: `relay:clients` → `{uuid: instanceId}` — connection registry with pub/sub for cross-instance forwarding |
| `SessionStore` | Redis `SET` with TTL — natural fit, already has expiry semantics |
| `NonceStore` | Redis `SET` with NX + TTL — atomic check-and-insert, perfect for replay prevention |
| `pending` Map | Redis Streams or pub/sub — instance A publishes request, instance B (holding the WebSocket) subscribes and forwards |

#### Architecture

```
   Load balancer (any strategy — no affinity needed)
        │
   ┌────┼────┬────────┐
   ▼    ▼    ▼        ▼
 Inst1 Inst2 Inst3  InstN     ← stateless relay instances
   │    │    │        │
   └────┴────┴────────┘
              │
         ┌────▼────┐
         │  Redis   │          ← connection registry + sessions + nonces
         └─────────┘
```

#### Request forwarding flow (cross-instance)

1. HTTP request arrives at instance A for UUID `abc123`.
2. Instance A looks up `abc123` in Redis → owned by instance B.
3. Instance A publishes request to Redis channel `relay:forward:B`.
4. Instance B receives the message, forwards to the local WebSocket.
5. Instance B publishes the response to Redis channel `relay:response:{requestId}`.
6. Instance A receives the response, returns it to the HTTP caller.

#### Trade-offs

- Adds operational dependency on Redis (availability, monitoring, backups).
- Adds latency per forwarded request (~1–2 ms Redis round-trip).
- Adds complexity for failure handling (what if the instance holding the
  WebSocket crashes between request and response?).
- Requires serialization/deserialization of request/response bodies through Redis.

Only justified if serving thousands of users across multiple machines or
regions.

### Tier 3: Go/Rust rewrite of the connection tier

For extreme scale (100K+ active connections with low-latency requirements):

| Factor | Node.js (current) | Go |
|---|---|---|
| Per-connection overhead | 4–7 KB (V8 heap) | 2–4 KB (goroutine stack) |
| GC pauses | 50–100 ms at scale | <1 ms (concurrent GC) |
| CPU parallelism | Single-threaded event loop | All cores used natively |
| Crypto performance | OpenSSL via native binding — fast | stdlib crypto — comparable |
| Binary deployment | Node.js runtime + node_modules | Single static binary (~10 MB) |
| Cold start | ~500 ms | ~10 ms |

A practical hybrid approach: rewrite only the **connection tier** (WebSocket
handling, request forwarding) in Go, while keeping the OAuth broker in
Node.js/Express (where Grant provides 200+ provider support for free).

This is a significant effort (~2–3 weeks) and only justified when the
connection count or latency requirements exceed what the Node.js
implementation can deliver.

---

## Quick reference: which tier to use

| Scenario | Recommended tier |
|---|---|
| Personal/small team (<1K daemons) | No scaling needed — single process is fine |
| Growing usage (1K–30K daemons) | Tier 1 — nginx + multiple workers on one machine |
| Multi-machine / multi-region (30K+ daemons) | Tier 2 — Redis-backed shared state |
| Extreme scale / edge deployment (100K+ active) | Tier 3 — Go/Rust connection tier |

---

## Lightweight optimizations (no architecture change)

Before scaling out, consider these in-process improvements:

1. **Drop Express for raw `node:http`** — removes middleware overhead, meaningful
   at high request rates.
2. **Drop Grant for manual OAuth flows** — reduces per-request memory and removes
   session middleware. Only worthwhile if you support a small number of providers.
3. **Use `Buffer.allocUnsafe`** for known-size allocations in hot paths (already
   done in crypto code).
4. **Tune V8 flags** — `--max-old-space-size=6144` on an 8 GB machine,
   `--optimize-for-size` to reduce per-object overhead.
5. **Raise OS limits** — `ulimit -n 200000`, `sysctl net.core.somaxconn=65535`,
   `net.ipv4.tcp_tw_reuse=1`.
