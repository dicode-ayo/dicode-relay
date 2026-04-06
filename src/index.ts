/**
 * dicode-relay entry point.
 *
 * Wires together:
 *  - RelayServer (WebSocket tunnel)
 *  - Grant OAuth middleware
 *  - Broker Express router
 * and starts an HTTP(S) server on PORT (default 8080).
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

const PORT = parseInt(process.env.PORT ?? "8080", 10);
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

// Session store
const sessions = new SessionStore();

// Grant middleware (OAuth broker)
const grantMiddleware = buildGrantMiddleware(PROVIDER_CONFIGS, BASE_URL);
app.use(grantMiddleware);

// Broker router
app.use(buildBrokerRouter(relayServer, sessions));

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
