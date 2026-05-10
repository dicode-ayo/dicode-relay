/**
 * Programmatic entry point for dicode-relay.
 *
 * `startServer(opts)` wires together the express app, relay WebSocket server,
 * Grant OAuth middleware, and broker router, and (unless `dryRun: true`) starts
 * an HTTP(S) listener on the configured port.
 *
 * This module has no top-level side effects: importing it neither parses
 * CLI args nor binds ports. The bin entrypoint (`src/index.ts`) layers
 * argv parsing + signal handling on top.
 *
 * `dryRun: true` performs full configuration + signing-key + provider wiring
 * (so config-shape and disk/permission errors surface) but skips `listen()`
 * and starts no keepalive timers. Callers receive a handle whose `close()` is
 * a safe no-op against the unbound socket.
 */

import { readFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import express from "express";
import { loadConfig, type RelayConfig } from "./config.js";
import { RelayServer } from "./relay/server.js";
import { buildGrantMiddleware } from "./broker/grant.js";
import { buildBrokerRouter } from "./broker/router.js";
import { MOCK_PROVIDER_KEY, buildE2EMockRouter, isE2EMockEnabled } from "./broker/e2e-mock.js";
import {
  buildProviderMap,
  type ProviderConfig,
  type PublicProviderInfo,
} from "./broker/providers.js";
import { SessionStore } from "./broker/sessions.js";
import { loadBrokerSigningKey } from "./shared/signing.js";
import { MetricsCollector } from "./status/metrics.js";
import { statusAuth } from "./status/auth.js";
import { renderStatusPage, buildStatusJson } from "./status/page.js";

export interface StartOpts {
  /** Path to relay.yaml. Mutually exclusive with `config`. */
  configPath?: string;
  /** Pre-loaded config object. Bypasses loadConfig. Mutually exclusive with `configPath`. */
  config?: RelayConfig;
  /** Env source for ${VAR} interpolation in YAML (default: process.env). */
  env?: NodeJS.ProcessEnv;
  /**
   * Validate + wire up everything but skip `httpServer.listen()`.
   * Used by `dicode-relay --check` and by external supervisors that want to
   * fail fast on config errors before committing to a port.
   */
  dryRun?: boolean;
}

export interface StartHandle {
  /** Underlying Node HTTP(S) server. `listening === false` when `dryRun: true`. */
  httpServer: HttpServer | HttpsServer;
  /** The RelayServer instance (WebSocket tunnel). */
  relayServer: RelayServer;
  /**
   * Gracefully shut down: closes the HTTP server and the RelayServer.
   * Safe no-op for the HTTP listener when `dryRun: true` (the socket was
   * never bound). Always closes the RelayServer to release in-memory state.
   */
  close: () => Promise<void>;
}

export async function startServer(opts: StartOpts = {}): Promise<StartHandle> {
  if (opts.configPath !== undefined && opts.config !== undefined) {
    throw new Error("startServer: pass either `configPath` or `config`, not both");
  }

  const env = opts.env ?? process.env;
  const config = opts.config ?? loadConfig(env, opts.configPath);
  const { server: serverCfg, relay: relayCfg, broker: brokerCfg, status: statusCfg } = config;

  // -------------------------------------------------------------------------
  // Express app + HTTP(S) server
  // -------------------------------------------------------------------------

  const app = express();

  let httpServer: HttpServer | HttpsServer;
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

  // -------------------------------------------------------------------------
  // Broker signing key
  // -------------------------------------------------------------------------

  const brokerKey = loadBrokerSigningKey(env, process.cwd(), brokerCfg.signing_key_file);

  // -------------------------------------------------------------------------
  // Relay server
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Metrics
  // -------------------------------------------------------------------------

  const metrics = new MetricsCollector();

  relayServer.on("client:connected", (uuid: string) => {
    metrics.registerClient(uuid);
  });
  relayServer.on("client:disconnected", (uuid: string) => {
    metrics.removeClient(uuid);
  });

  // -------------------------------------------------------------------------
  // OAuth broker
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // Inbound request forwarding — shared handler
  // -------------------------------------------------------------------------

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

  // Public provider metadata — no secret values exposed.
  app.get("/providers", (_req, res) => {
    const list = Array.from(realProviders.entries()).map(
      ([key, cfg]): PublicProviderInfo => ({
        key,
        pkce: cfg.pkce,
        scopes: cfg.scopes,
        secret_required: cfg.clientSecret !== undefined,
        // buildProviderMap already skips providers with empty clientId, so every
        // entry in realProviders has a non-empty clientId → always true here.
        // The field exists for API forward-compatibility with a future
        // "show unconfigured providers" mode.
        configured: cfg.clientId !== "",
      }),
    );
    res.json(list);
  });

  // -------------------------------------------------------------------------
  // Listen (skipped in dryRun)
  // -------------------------------------------------------------------------

  const close = async (): Promise<void> => {
    // Always close the relay server (clears nonces, terminates client sockets,
    // shuts down the WebSocketServer). In dryRun mode the WSS is attached to
    // an unbound HTTP server, but RelayServer.close() still cleans up safely.
    await relayServer.close();

    // If the HTTP server was never bound (dryRun), `close()` invokes its
    // callback with an ERR_SERVER_NOT_RUNNING error. Treat that as a no-op.
    await new Promise<void>((resolve, reject) => {
      if (!httpServer.listening) {
        resolve();
        return;
      }
      httpServer.close((err) => {
        if (err !== undefined) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  };

  if (opts.dryRun === true) {
    return { httpServer, relayServer, close };
  }

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(serverCfg.port, () => {
      httpServer.removeListener("error", reject);
      console.log(`dicode-relay listening on port ${String(serverCfg.port)}`);
      console.log(`Base URL: ${serverCfg.base_url}`);
      console.log(`Providers: ${[...brokerProviders.keys()].join(", ") || "(none configured)"}`);
      resolve();
    });
  });

  return { httpServer, relayServer, close };
}
