/**
 * Programmatic entry point for dicode-relay.
 *
 * `startServer(opts)` wires together the express app, relay WebSocket server,
 * Grant OAuth middleware, and broker router, and (unless `dryRun: true`)
 * starts two listeners:
 *
 *   - the public listener (`server.port`): webhooks (/u/:uuid/hooks/*),
 *     OAuth routes, /status, /health. Plain HTTP or one-cert TLS — typically
 *     behind a TLS-terminating proxy (Cloudflare, nginx).
 *   - the mTLS listener (`server.mtls.port`): the daemon control channel.
 *     Always TLS with `requestCert: true` — the peer certificate carries the
 *     daemon identity. This port must be reachable with END-TO-END TLS
 *     passthrough (L4 load balancing only); a terminating proxy in front of
 *     it would strip the client certificate.
 *
 * This module has no top-level side effects: importing it neither parses
 * CLI args nor binds ports. The bin entrypoint (`src/index.ts`) layers
 * argv parsing + signal handling on top.
 *
 * `dryRun: true` performs full configuration + signing-key + provider wiring
 * (so config-shape and disk/permission errors surface) but skips `listen()`
 * and starts no keepalive timers. Callers receive a handle whose `close()` is
 * a safe no-op against the unbound sockets.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import express from "express";
import { generateSelfSignedServerCert } from "./shared/certs.js";
import { ConfigSchema, loadConfig, type RelayConfig } from "./config.js";
import { RelayServer } from "./relay/server.js";
import { buildGrantMiddleware } from "./broker/grant.js";
import { buildBrokerRouter } from "./broker/router.js";
import { MOCK_PROVIDER_KEY, buildE2EMockRouter, isE2EMockEnabled } from "./broker/e2e-mock.js";
import {
  buildProviderMap,
  type ProviderConfig,
  type PublicProviderInfo,
} from "./broker/providers.js";
import { SeenSet } from "./broker/sessions.js";
import { buildFlowSession } from "./broker/flow-session.js";
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
  /** Public listener (webhooks/OAuth/status). `listening === false` when `dryRun: true`. */
  httpServer: HttpServer | HttpsServer;
  /** mTLS daemon control-channel listener. `listening === false` when `dryRun: true`. */
  mtlsServer: HttpsServer;
  /** The RelayServer instance (WebSocket tunnel). */
  relayServer: RelayServer;
  /**
   * Gracefully shut down: closes both listeners and the RelayServer.
   * Safe no-op for the listeners when `dryRun: true` (sockets never bound).
   * Always closes the RelayServer to release in-memory state.
   */
  close: () => Promise<void>;
}

export async function startServer(opts: StartOpts = {}): Promise<StartHandle> {
  if (opts.configPath !== undefined && opts.config !== undefined) {
    throw new Error("startServer: pass either `configPath` or `config`, not both");
  }

  const env = opts.env ?? process.env;
  // Re-validate caller-supplied configs through Zod. The TS `RelayConfig` type
  // gives compile-time safety only; JS/Deno callers (where TS types are erased
  // at the npm package boundary) can pass anything that *looks* like the shape.
  // Routing untrusted input through `ConfigSchema.parse` makes this a defensive
  // library entry point — costs one cheap parse on startup; catches numeric
  // ports passed as strings, missing nested keys, etc. before they reach
  // `readFileSync` / `loadBrokerSigningKey`.
  const config =
    opts.config !== undefined ? ConfigSchema.parse(opts.config) : loadConfig(env, opts.configPath);
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
  // mTLS control-channel listener
  // -------------------------------------------------------------------------

  // The daemon WS endpoint lives on its own TLS listener with client
  // certificates requested. The chain is NOT verified (`rejectUnauthorized:
  // false`) — a daemon's self-signed cert IS its identity; RelayServer
  // rejects connections without a P-256 client cert at the WS layer.
  const mtlsCert = await resolveMtlsCert(serverCfg, opts.dryRun === true);
  const mtlsServer = createHttpsServer({
    cert: mtlsCert.certPem,
    key: mtlsCert.keyPem,
    requestCert: true,
    rejectUnauthorized: false,
  });
  // Non-upgrade HTTP requests have no business on this port.
  mtlsServer.on("request", (_req, res) => {
    res.writeHead(426, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "WebSocket upgrade required" }));
  });

  // -------------------------------------------------------------------------
  // Broker signing key
  // -------------------------------------------------------------------------

  // dryRun must not write a signing key to disk — derive an ephemeral
  // in-memory key instead so the broker router can still wire up.
  const allowAutoGenerate = opts.dryRun !== true;
  const brokerKey = loadBrokerSigningKey(
    env,
    process.cwd(),
    brokerCfg.signing_key_file,
    allowAutoGenerate,
    serverCfg.multi_instance,
  );

  // -------------------------------------------------------------------------
  // Relay server
  // -------------------------------------------------------------------------

  const relayServer = new RelayServer({
    baseUrl: serverCfg.base_url,
    server: mtlsServer,
    pingIntervalMs: relayCfg.ping_interval_ms,
    pongTimeoutMs: relayCfg.pong_timeout_ms,
    requestTimeoutMs: relayCfg.request_timeout_ms,
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
  const seen = new SeenSet(brokerCfg.session_ttl_ms);

  // Browser-facing OAuth flow cookie. Mounted before Grant and the broker/mock
  // routers so `req.session` is available to all of them. Grant requires it for
  // its own per-flow state; the broker seals its flow state into the same
  // cookie. `secure` follows the public base URL's scheme.
  const flowCookieSecure = /^(https|wss):/i.test(serverCfg.base_url);
  app.use(
    buildFlowSession(brokerKey, {
      secure: flowCookieSecure,
      maxAgeMs: brokerCfg.session_ttl_ms,
    }),
  );

  // If the E2E mock flag is set, include "mock" so /auth/mock is accepted.
  // Grant must NOT receive the mock entry — /connect/mock is handled by the
  // e2e-mock router.
  const brokerProviders = new Map<string, ProviderConfig>(realProviders);
  if (isE2EMockEnabled(env)) {
    brokerProviders.set(MOCK_PROVIDER_KEY, {
      grantKey: MOCK_PROVIDER_KEY,
      // Placeholder — never reaches Grant (realProviders only). Satisfies the
      // providers.has non-empty check.
      clientId: "mock-e2e-not-a-real-credential",
      pkce: true,
      scopes: [],
    });
    console.warn(
      "broker: DICODE_E2E_MOCK_PROVIDER enabled — mock provider registered. DO NOT USE IN PRODUCTION.",
    );
    // Mount before Grant so /connect/mock is intercepted first.
    app.use(buildE2EMockRouter(relayServer, brokerKey));
  }

  const grantMiddleware = buildGrantMiddleware(realProviders, serverCfg.base_url);
  app.use(grantMiddleware);
  app.use(
    buildBrokerRouter(
      relayServer,
      seen,
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

  // Raw query string (leading "?" included) exactly as received. Taken from
  // originalUrl rather than req.query so percent-encoding survives verbatim —
  // a parse/re-serialize round-trip would mangle encoded values. The daemon
  // splits it off again before its path allow-list check.
  function rawQuery(req: express.Request): string {
    const i = req.originalUrl.indexOf("?");
    return i === -1 ? "" : req.originalUrl.slice(i);
  }

  // /u/:uuid/dicode.js — client SDK served by the daemon
  app.get("/u/:uuid/dicode.js", express.raw({ type: "*/*", limit: "5mb" }), (req, res) => {
    forwardToClient(req, res, req.params.uuid, "/dicode.js" + rawQuery(req));
  });

  // /u/:uuid/hooks/* — webhook requests forwarded to daemon
  app.all("/u/:uuid/hooks/*path", express.raw({ type: "*/*", limit: "5mb" }), (req, res) => {
    const uuid = req.params.uuid;
    const pathParam = req.params.path;
    const pathStr = Array.isArray(pathParam) ? pathParam.join("/") : pathParam;
    const hookPath = "/hooks/" + pathStr + rawQuery(req);

    forwardToClient(req, res, uuid, hookPath);
  });

  // Status dashboard. `statusCfg.password` is undefined when the YAML omits
  // the key (or sets it to null) — `statusAuth(undefined)` then answers every
  // /status and /api/status request with 404 ("status page not configured").
  // Zod rejects an empty string at load time so we don't need to defensively
  // map "" → undefined here.
  const statusPassword = statusCfg.password;
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
    const list = Array.from(realProviders.entries()).map(([key, cfg]): PublicProviderInfo => ({
      key,
      pkce: cfg.pkce,
      scopes: cfg.scopes,
      secret_required: cfg.clientSecret !== undefined,
      // buildProviderMap already skips providers with empty clientId, so every
      // entry in realProviders has a non-empty clientId → always true here.
      // The field exists for API forward-compatibility with a future
      // "show unconfigured providers" mode.
      configured: cfg.clientId !== "",
    }));
    res.json(list);
  });

  // -------------------------------------------------------------------------
  // Listen (skipped in dryRun)
  // -------------------------------------------------------------------------

  const close = async (): Promise<void> => {
    // Always close the relay server (terminates client sockets, shuts down
    // the WebSocketServer). In dryRun mode the WSS is attached to an unbound
    // HTTPS server, but RelayServer.close() still cleans up safely.
    await relayServer.close();

    // If a listener was never bound (dryRun), `close()` invokes its callback
    // with an ERR_SERVER_NOT_RUNNING error. Treat that as a no-op.
    const closeListener = (srv: HttpServer | HttpsServer): Promise<void> =>
      new Promise<void>((resolve, reject) => {
        if (!srv.listening) {
          resolve();
          return;
        }
        srv.close((err) => {
          if (err !== undefined) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    await closeListener(httpServer);
    await closeListener(mtlsServer);
  };

  if (opts.dryRun === true) {
    return { httpServer, mtlsServer, relayServer, close };
  }

  const listen = (srv: HttpServer | HttpsServer, port: number): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(port, () => {
        srv.removeListener("error", reject);
        resolve();
      });
    });

  await listen(httpServer, serverCfg.port);
  await listen(mtlsServer, serverCfg.mtls.port);
  console.log(`dicode-relay listening on port ${String(serverCfg.port)}`);
  console.log(`dicode-relay mTLS control channel on port ${String(serverCfg.mtls.port)}`);
  console.log(`Base URL: ${serverCfg.base_url}`);
  console.log(`Providers: ${[...brokerProviders.keys()].join(", ") || "(none configured)"}`);

  return { httpServer, mtlsServer, relayServer, close };
}

// ---------------------------------------------------------------------------
// mTLS certificate resolution
// ---------------------------------------------------------------------------

const AUTO_MTLS_CERT_FILENAME = "relay-mtls-cert.pem";
const AUTO_MTLS_KEY_FILENAME = "relay-mtls-key.pem";

interface MtlsCertPems {
  certPem: string;
  keyPem: string;
}

/**
 * Resolve the mTLS listener's server certificate.
 *
 * Resolution order:
 *   1. `server.mtls.cert_file` + `key_file` — operator-managed (e.g. the
 *      wildcard LE cert). Must exist; never auto-generates at an explicit
 *      path (same rationale as loadBrokerSigningKey).
 *   2. Fall back to `server.tls.*` when set — reuse the public listener cert.
 *   3. Auto-generate a persistent self-signed dev cert at
 *      `<cwd>/relay-mtls-cert.pem` / `-key.pem` (CA:FALSE — required by
 *      rustls-based daemons). Daemons trust it via an explicit CA option.
 *      In dryRun the cert is ephemeral and never written to disk.
 *
 * When `server.multi_instance` is set, the auto-generate fallback (step 3) is
 * a hard error: a per-cwd self-signed cert diverges across instances and
 * breaks the pin daemons hold via `relay.ca_file`. Operators must supply a
 * shared cert (step 1, or the shared step-2 `server.tls` cert).
 */
async function resolveMtlsCert(
  serverCfg: RelayConfig["server"],
  dryRun: boolean,
): Promise<MtlsCertPems> {
  const explicit = serverCfg.mtls;
  if (explicit.cert_file !== "" && explicit.key_file !== "") {
    for (const f of [explicit.cert_file, explicit.key_file]) {
      if (!existsSync(f)) {
        throw new Error(
          `server.mtls points to a missing file: ${f}. ` +
            `Create the cert/key pair or unset server.mtls.cert_file/key_file ` +
            `to fall back to server.tls or an auto-generated dev cert.`,
        );
      }
    }
    return {
      certPem: readFileSync(explicit.cert_file, "utf8"),
      keyPem: readFileSync(explicit.key_file, "utf8"),
    };
  }

  if (serverCfg.tls.cert_file !== "" && serverCfg.tls.key_file !== "") {
    return {
      certPem: readFileSync(serverCfg.tls.cert_file, "utf8"),
      keyPem: readFileSync(serverCfg.tls.key_file, "utf8"),
    };
  }

  if (serverCfg.multi_instance) {
    // A per-cwd self-signed cert — freshly generated or read back from an
    // earlier auto-generate — diverges across instances and fails the pin
    // daemons hold via relay.ca_file. Refuse to fall back here.
    throw new Error(
      `server.multi_instance is set but no shared mTLS server certificate was supplied. ` +
        `Daemons pin the relay's mTLS cert (relay.ca_file); an auto-generated per-instance ` +
        `cert fails pinning against every instance but the one that generated it. Supply a ` +
        `cert identical across all instances via server.mtls.cert_file/key_file (or a shared ` +
        `server.tls.cert_file/key_file), or unset server.multi_instance for single-instance mode.`,
    );
  }

  const certPath = join(process.cwd(), AUTO_MTLS_CERT_FILENAME);
  const keyPath = join(process.cwd(), AUTO_MTLS_KEY_FILENAME);
  if (existsSync(certPath) && existsSync(keyPath)) {
    return {
      certPem: readFileSync(certPath, "utf8"),
      keyPem: readFileSync(keyPath, "utf8"),
    };
  }

  const hosts: string[] = [];
  try {
    const host = new URL(serverCfg.base_url).hostname;
    if (host !== "") hosts.push(host);
  } catch {
    // base_url unparsable — SANs default to localhost/127.0.0.1 only.
  }
  const generated = await generateSelfSignedServerCert({ hosts });
  if (!dryRun) {
    mkdirSync(dirname(certPath), { recursive: true });
    writeFileSync(certPath, generated.certPem, { mode: 0o644 });
    writeFileSync(keyPath, generated.keyPem, { mode: 0o600 });
    console.warn(
      `relay: no shared mTLS server cert configured — generated a per-instance self-signed cert ` +
        `at ${certPath}. SINGLE-INSTANCE ONLY: daemons pin this cert via relay.ca_file, so a ` +
        `second instance with its own auto-generated cert would be rejected. For multi-instance ` +
        `deployments set server.multi_instance: true and hand every instance the same ` +
        `server.mtls.cert_file/key_file. Point daemons' relay.ca_file at this cert, or set ` +
        `server.mtls.cert_file/key_file to use an operator-managed certificate.`,
    );
  }
  return generated;
}
