/**
 * dicode-relay entry point.
 *
 * Wires together:
 *  - RelayServer (WebSocket tunnel)
 *  - Grant OAuth middleware
 *  - Broker Express router
 * and starts an HTTP(S) server on PORT (default 5553).
 *
 * TLS: if TLS_CERT_FILE and TLS_KEY_FILE are set, creates an HTTPS server.
 * Otherwise, creates a plain HTTP server (for use behind Cloudflare/nginx TLS termination).
 */

import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import express from "express";
import { RelayServer } from "./relay/server.js";
import { buildGrantMiddleware } from "./broker/grant.js";
import { buildBrokerRouter } from "./broker/router.js";
import { SessionStore } from "./broker/sessions.js";
import { PROVIDER_CONFIGS } from "./broker/providers.js";
import { MetricsCollector } from "./status/metrics.js";
import { statusAuth } from "./status/auth.js";
import { renderStatusPage, buildStatusJson } from "./status/page.js";

const PORT = parseInt(process.env.PORT ?? "5553", 10);
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT.toString()}`;
const TLS_CERT_FILE = process.env.TLS_CERT_FILE;
const TLS_KEY_FILE = process.env.TLS_KEY_FILE;

const app = express();

// Create the HTTP/HTTPS server before wiring the WebSocket server
// so both share the same port.
let httpServer: ReturnType<typeof createHttpServer> | ReturnType<typeof createHttpsServer>;

if (TLS_CERT_FILE !== undefined && TLS_KEY_FILE !== undefined) {
  httpServer = createHttpsServer(
    {
      cert: readFileSync(TLS_CERT_FILE),
      key: readFileSync(TLS_KEY_FILE),
    },
    app,
  );
} else {
  httpServer = createHttpServer(app);
}

// Relay server attaches to the same HTTP server, sharing port
const relayServer = new RelayServer({ baseUrl: BASE_URL, server: httpServer });

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

// Session store
const sessions = new SessionStore();

// Grant middleware (OAuth broker)
const grantMiddleware = buildGrantMiddleware(PROVIDER_CONFIGS, BASE_URL);
app.use(grantMiddleware);

// Broker router
app.use(buildBrokerRouter(relayServer, sessions));

// ---------------------------------------------------------------------------
// Inbound request forwarding — shared handler
// ---------------------------------------------------------------------------
// Accepts any HTTP method. Reads the raw body, forwards via the WebSocket tunnel
// to the connected daemon, and streams the daemon's response back to the caller.
// URL rewriting handled daemon-side — see dicode-core feat/transparent-relay-proxy

function forwardToClient(req: express.Request, res: express.Response, uuid: string, forwardPath: string): void {
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
app.get("/status", statusAuth(STATUS_PASSWORD), (_req, res) => {
  res.type("html").send(renderStatusPage(metrics.snapshot()));
});

app.get("/api/status", statusAuth(STATUS_PASSWORD), (_req, res) => {
  res.json(buildStatusJson(metrics.snapshot()));
});

// Health check
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

// Start listening
httpServer.listen(PORT, () => {
  console.log(`dicode-relay listening on port ${PORT.toString()}`);
  console.log(`Base URL: ${BASE_URL}`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down");
  httpServer.close(() => {
    process.exit(0);
  });
  void relayServer.close();
});
