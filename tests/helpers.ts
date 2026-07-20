/**
 * Shared test helpers. All defaults come from the Zod config schema
 * so tests never duplicate magic numbers.
 *
 * Relay-server tests run against a real mTLS HTTPS listener on 127.0.0.1
 * (port 0) — the peer certificate IS the protocol, so there is no
 * plain-WS shortcut.
 */

import { createServer as createHttpsServer, Agent as HttpsAgent, type Server } from "node:https";
import WebSocket from "ws";
import { defaultConfig } from "../src/config.js";
import { RelayServer, type RelayServerOptions } from "../src/relay/server.js";
import { generateSelfSignedServerCert, type GeneratedCert } from "../src/shared/certs.js";
import { Identity } from "../src/client/identity.js";

const cfg = defaultConfig();

/** Session TTL from Zod defaults. */
export const testSessionTtlMs = cfg.broker.session_ttl_ms;

// ---------------------------------------------------------------------------
// mTLS relay fixture
// ---------------------------------------------------------------------------

// One server cert for the whole test process — generation costs a few ms and
// nothing in the suite depends on per-instance server certs.
let serverCertPromise: Promise<GeneratedCert> | undefined;
export function testServerCert(): Promise<GeneratedCert> {
  serverCertPromise ??= generateSelfSignedServerCert({ hosts: ["localhost"] });
  return serverCertPromise;
}

export interface MtlsRelayFixture {
  relay: RelayServer;
  httpsServer: Server;
  port: number;
  /** wss:// URL of the mTLS listener. */
  url: string;
  /** PEM the client should pass as `ca` to trust the server cert. */
  ca: string;
  close: () => Promise<void>;
}

/** Start a RelayServer on a fresh mTLS listener bound to 127.0.0.1:0. */
export async function startMtlsRelay(
  overrides?: Partial<Omit<RelayServerOptions, "server">>,
): Promise<MtlsRelayFixture> {
  const serverCert = await testServerCert();
  const httpsServer = createHttpsServer({
    cert: serverCert.certPem,
    key: serverCert.keyPem,
    requestCert: true,
    rejectUnauthorized: false,
  });
  const relay = new RelayServer(testRelayOpts(httpsServer, overrides));
  await new Promise<void>((resolve, reject) => {
    httpsServer.once("error", reject);
    httpsServer.listen(0, "127.0.0.1", () => {
      httpsServer.removeListener("error", reject);
      resolve();
    });
  });
  const addr = httpsServer.address();
  if (addr === null || typeof addr === "string") throw new Error("no listener address");
  const port = addr.port;
  return {
    relay,
    httpsServer,
    port,
    url: `wss://127.0.0.1:${String(port)}`,
    ca: serverCert.certPem,
    close: async () => {
      await relay.close();
      await new Promise<void>((resolve) => {
        if (!httpsServer.listening) {
          resolve();
          return;
        }
        httpsServer.close(() => {
          resolve();
        });
      });
    },
  };
}

/** Relay server options with all Zod defaults — merge with test overrides. */
export function testRelayOpts(
  server: Server,
  overrides?: Partial<Omit<RelayServerOptions, "server">>,
): RelayServerOptions {
  return {
    baseUrl: "ws://localhost",
    server,
    pingIntervalMs: cfg.relay.ping_interval_ms,
    pongTimeoutMs: cfg.relay.pong_timeout_ms,
    requestTimeoutMs: cfg.relay.request_timeout_ms,
    ...overrides,
  };
}

export interface TestDaemon {
  identity: Identity;
  cert: GeneratedCert;
  /** Agent carrying the client cert — pass to `new WebSocket(url, {agent})`. */
  agent: HttpsAgent;
}

/** Generate a fresh daemon identity + minted client cert + dial agent. */
export async function testDaemon(fixture: Pick<MtlsRelayFixture, "ca">): Promise<TestDaemon> {
  const identity = await Identity.generate();
  const cert = await identity.mintClientCert();
  const agent = new HttpsAgent({
    cert: cert.certPem,
    key: cert.keyPem,
    ca: fixture.ca,
  });
  return { identity, cert, agent };
}

/**
 * Dial the fixture with the daemon's client cert, send the v4 hello, and
 * resolve with the open socket once the welcome frame arrives.
 */
export async function connectDaemon(
  fixture: Pick<MtlsRelayFixture, "url">,
  daemon: TestDaemon,
): Promise<{ ws: WebSocket; welcome: Record<string, unknown> }> {
  const ws = new WebSocket(fixture.url, { agent: daemon.agent });
  const welcome = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("welcome timeout"));
      ws.terminate();
    }, 5000);
    ws.on("open", () => {
      ws.send(helloEnvelope({ decrypt_pubkey: daemon.identity.decryptPubkeyB64 }));
    });
    ws.on("message", (data: Buffer | string) => {
      const w = parseWelcome(data);
      if (w !== null) {
        clearTimeout(timer);
        resolve(w);
        return;
      }
      const e = parseError(data);
      if (e !== null) {
        clearTimeout(timer);
        reject(new Error(`relay error: ${e.message}`));
      }
    });
    ws.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
  return { ws, welcome };
}

// ---------------------------------------------------------------------------
// Protobuf-envelope wire helpers
//
// The relay protocol is carried in an envelope with a single top-level
// variant key (e.g. {"hello": {...}}, {"welcome": {...}}).
// Tests that build or parse raw WebSocket frames go through these helpers so
// the envelope shape lives in one place.
// ---------------------------------------------------------------------------

/** Parse an outgoing server frame and return its welcome payload, or null. */
export function parseWelcome(data: Buffer | string): Record<string, unknown> | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const w = env.welcome as Record<string, unknown> | undefined;
  return w ?? null;
}

/** Parse an outgoing server frame and return its error payload, or null. */
export function parseError(data: Buffer | string): { message: string } | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const e = env.error as { message: string } | undefined;
  return e ?? null;
}

/** Parse an outgoing server frame and return the request payload, or null. */
export function parseRequest(
  data: Buffer | string,
): { id: string; method: string; path: string; body: string } | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const r = env.request as { id: string; method: string; path: string; body: string } | undefined;
  return r ?? null;
}

/** Build a client → server hello envelope (fields use snake_case per proto). */
export function helloEnvelope(fields: { decrypt_pubkey: string }): string {
  return JSON.stringify({ hello: fields });
}

/** Build a client → server response envelope. Headers are wrapped in {values}. */
export function responseEnvelope(resp: {
  id: string;
  status: number;
  headers?: Record<string, string[]>;
  body: string;
}): string {
  const wireHeaders: Record<string, { values: string[] }> = {};
  for (const [k, v] of Object.entries(resp.headers ?? {})) {
    wireHeaders[k] = { values: v };
  }
  return JSON.stringify({
    response: { id: resp.id, status: resp.status, headers: wireHeaders, body: resp.body },
  });
}
