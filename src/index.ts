#!/usr/bin/env node
/**
 * dicode-relay entry point.
 *
 * Wires together:
 *  - RelayServer (WebSocket tunnel)
 *  - Grant OAuth middleware
 *  - Broker Express router
 * and starts an HTTP(S) server on the configured port (default 5553).
 *
 * Configuration: reads relay.yaml (or --config / RELAY_CONFIG env).
 * Falls back to process.env if no YAML file exists.
 */

import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import express from "express";
import { loadConfig } from "./config.js";
import { RelayServer } from "./relay/server.js";
import { buildGrantMiddleware } from "./broker/grant.js";
import { buildBrokerRouter } from "./broker/router.js";
import { MOCK_PROVIDER_KEY, buildE2EMockRouter, isE2EMockEnabled } from "./broker/e2e-mock.js";
import { buildProviderMap, type ProviderConfig } from "./broker/providers.js";
import { SessionStore } from "./broker/sessions.js";
import { loadBrokerSigningKey } from "./broker/signing.js";
import { MetricsCollector } from "./status/metrics.js";
import { statusAuth } from "./status/auth.js";
import { renderStatusPage, buildStatusJson } from "./status/page.js";

// ---------------------------------------------------------------------------
// Load config
// ---------------------------------------------------------------------------

const config = loadConfig();
const { server: serverCfg, relay: relayCfg, broker: brokerCfg, status: statusCfg } = config;

// ---------------------------------------------------------------------------
// Express app + HTTP(S) server
// ---------------------------------------------------------------------------

const app = express();

let httpServer: ReturnType<typeof createHttpServer> | ReturnType<typeof createHttpsServer>;

if (serverCfg.tls.cert_file !== "" && serverCfg.tls.key_file !== "") {
  httpServer = createHttpsServer(
    {
      cert: readFileSync(serverCfg.tls.cert_file),
      key: readFileSync(serverCfg.tls.key_file),
    },
    app,
  );
} else {
  httpServer = createHttpServer(app);
}

// ---------------------------------------------------------------------------
// Broker signing key
// ---------------------------------------------------------------------------

const brokerKey = loadBrokerSigningKey(process.env, process.cwd(), brokerCfg.signing_key_file);

// ---------------------------------------------------------------------------
// Relay server
// ---------------------------------------------------------------------------

const relayServer = new RelayServer({
  baseUrl: serverCfg.base_url,
  server: httpServer,
  timestampToleranceS: relayCfg.timestamp_tolerance_s,
  pingIntervalMs: relayCfg.ping_interval_ms,
  pongTimeoutMs: relayCfg.pong_timeout_ms,
  requestTimeoutMs: relayCfg.request_timeout_ms,
  nonceTtlMs: relayCfg.nonce_ttl_ms,
  brokerPubkey: brokerKey.publicKeyBase64,
});

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

const metrics = new MetricsCollector();

relayServer.on("client:connected", (uuid: string) => {
  metrics.registerClient(uuid);
});
relayServer.on("client:disconnected", (uuid: string) => {
  metrics.removeClient(uuid);
});

// ---------------------------------------------------------------------------
// OAuth broker
// ---------------------------------------------------------------------------

const realProviders = buildProviderMap(config);
const sessions = new SessionStore(brokerCfg.session_ttl_ms);

// Providers passed to the broker router (session creation in /auth/:provider).
// If the E2E mock flag is set, include "mock" here so /auth/mock is accepted.
// Grant must NOT receive the mock entry — /connect/mock is handled by the
// e2e-mock router, and Grant would otherwise try to dispatch it upstream.
const brokerProviders = new Map<string, ProviderConfig>(realProviders);
if (isE2EMockEnabled()) {
  brokerProviders.set(MOCK_PROVIDER_KEY, {
    grantKey: MOCK_PROVIDER_KEY,
    // Obviously-fake placeholder — never reaches Grant (see buildGrantMiddleware
    // call below, which is passed realProviders only). Exists solely to satisfy
    // the non-empty check in providers.has/buildProviderMap invariants.
    clientId: "mock-e2e-not-a-real-credential",
    pkce: true,
    scopes: [],
  });
  console.warn(
    "broker: DICODE_E2E_MOCK_PROVIDER enabled — mock provider registered. DO NOT USE IN PRODUCTION.",
  );
  // Mount BEFORE Grant so /connect/mock is intercepted and Grant never sees
  // it. Also exposes /_test/deliver for low-level wire-shape testing.
  app.use(buildE2EMockRouter(relayServer, sessions, brokerKey));
}

const grantMiddleware = buildGrantMiddleware(realProviders, serverCfg.base_url);
app.use(grantMiddleware);
app.use(
  buildBrokerRouter(
    relayServer,
    sessions,
    brokerProviders,
    relayCfg.timestamp_tolerance_s,
    brokerKey,
  ),
);

// ---------------------------------------------------------------------------
// Inbound request forwarding — shared handler
// ---------------------------------------------------------------------------

function forwardToClient(
  req: express.Request,
  res: express.Response,
  uuid: string,
  forwardPath: string,
): void {
  if (!relayServer.hasClient(uuid)) {
    res.status(502).json({ error: "daemon not connected" });
    return;
  }

  const headers: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers[key] = Array.isArray(value) ? value : [value];
  }

  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

  metrics.record(uuid);

  relayServer
    .forward(uuid, req.method, forwardPath, headers, body)
    .then((response) => {
      res.status(response.status);
      for (const [k, vals] of Object.entries(response.headers)) {
        for (const v of vals) {
          res.append(k, v);
        }
      }
      if (response.body !== "") {
        res.send(Buffer.from(response.body, "base64"));
      } else {
        res.end();
      }
    })
    .catch(() => {
      res.status(504).json({ error: "forwarding failed or timed out" });
    });
}

// /u/:uuid/dicode.js — client SDK served by the daemon
app.get("/u/:uuid/dicode.js", express.raw({ type: "*/*", limit: "5mb" }), (req, res) => {
  forwardToClient(req, res, req.params.uuid, "/dicode.js");
});

// /u/:uuid/hooks/* — webhook requests forwarded to daemon
app.all("/u/:uuid/hooks/*path", express.raw({ type: "*/*", limit: "5mb" }), (req, res) => {
  const uuid = req.params.uuid;
  const pathParam = req.params.path;
  const pathStr = Array.isArray(pathParam) ? pathParam.join("/") : pathParam;
  const hookPath = "/hooks/" + pathStr;

  forwardToClient(req, res, uuid, hookPath);
});

// Status dashboard (password-protected)
const statusPassword = statusCfg.password !== "" ? statusCfg.password : undefined;
app.get("/status", statusAuth(statusPassword), (_req, res) => {
  res.type("html").send(renderStatusPage(metrics.snapshot()));
});

app.get("/api/status", statusAuth(statusPassword), (_req, res) => {
  res.json(buildStatusJson(metrics.snapshot()));
});

// Health check
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// Start listening
httpServer.listen(serverCfg.port, () => {
  console.log(`dicode-relay listening on port ${String(serverCfg.port)}`);
  console.log(`Base URL: ${serverCfg.base_url}`);
  console.log(`Providers: ${[...brokerProviders.keys()].join(", ") || "(none configured)"}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down");
  httpServer.close(() => {
    process.exit(0);
  });
  void relayServer.close();
});
