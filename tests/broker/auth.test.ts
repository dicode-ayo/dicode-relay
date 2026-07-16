/**
 * Broker auth route tests — real crypto, in-process mTLS RelayServer, no mocks.
 */

import { randomBytes, createECDH } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildBrokerRouter } from "../../src/broker/router.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SessionStore, type Session } from "../../src/broker/sessions.js";
import { Identity } from "../../src/client/identity.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseRequest,
  responseEnvelope,
  testSessionTtlMs,
  type MtlsRelayFixture,
} from "../helpers.js";

/** Test provider map with a single "github" provider. */
function testProviders(): ReadonlyMap<string, ProviderConfig> {
  return new Map([
    [
      "github",
      { grantKey: "github", clientId: "test-client-id", pkce: true, scopes: ["user", "repo"] },
    ],
  ]);
}

/** Build the signed /auth/:provider URL for a daemon identity. */
async function buildAuthUrl(
  httpPort: number,
  identity: Identity,
  provider: string,
  sessionId: string,
  opts?: { timestamp?: number; sig?: string },
): Promise<string> {
  const pkceChallenge = randomBytes(32).toString("base64url");
  const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000);
  const sig =
    opts?.sig ?? (await identity.signAuthPayload(sessionId, pkceChallenge, provider, timestamp));

  return (
    `http://localhost:${httpPort.toString()}/auth/${provider}` +
    `?session=${encodeURIComponent(sessionId)}` +
    `&challenge=${encodeURIComponent(pkceChallenge)}` +
    `&relay_uuid=${identity.uuid}` +
    `&sig=${encodeURIComponent(sig)}` +
    `&timestamp=${timestamp.toString()}`
  );
}

/** Make an HTTP GET request and return status + body */
async function httpGet(url: string): Promise<{ status: number; body: string }> {
  const response = await fetch(url);
  const body = await response.text();
  return { status: response.status, body };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("Broker /auth/:provider", () => {
  let fixture: MtlsRelayFixture;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    sessions = new SessionStore(testSessionTtlMs);

    const app = express();
    app.use(buildBrokerRouter(fixture.relay, sessions, testProviders()));

    await new Promise<void>((resolve) => {
      httpServer = app.listen(0, () => {
        resolve();
      });
    });

    const addr = httpServer.address();
    if (addr === null || typeof addr === "string") throw new Error("No port");
    httpPort = addr.port;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => {
        if (err !== undefined) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
    await fixture.close();
    sessions.clear();
  });

  it("valid request with correct sig → 302 redirect to Grant", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const url = await buildAuthUrl(httpPort, daemon.identity, "github", sessionId);
    const response = await fetch(url, { redirect: "manual" });

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).toContain("/connect/github");

    // Session should be stored
    expect(sessions.get(sessionId)).toBeDefined();
    expect(sessions.get(sessionId)?.provider).toBe("github");

    ws.terminate();
  });

  it("missing relay_uuid → 400", async () => {
    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const ts = Math.floor(Date.now() / 1000).toString();
    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=${sessionId}&challenge=abc&sig=sig&timestamp=${ts}`;

    const { status } = await httpGet(url);
    expect(status).toBe(400);
  });

  it("UUID not in relay registry → 403", async () => {
    // Fresh identity that never connects to the relay.
    const identity = await Identity.generate();

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const url = await buildAuthUrl(httpPort, identity, "github", sessionId);

    const { status } = await httpGet(url);
    expect(status).toBe(403);
  });

  it("bad ECDSA signature → 403", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    // Use a random (invalid) signature
    const badSig = randomBytes(64).toString("base64");
    const url = await buildAuthUrl(httpPort, daemon.identity, "github", sessionId, {
      sig: badSig,
    });

    const { status } = await httpGet(url);
    expect(status).toBe(403);

    ws.terminate();
  });

  it("stale timestamp → 403", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const timestamp = Math.floor(Date.now() / 1000) - 60; // 60 seconds ago
    const url = await buildAuthUrl(httpPort, daemon.identity, "github", sessionId, { timestamp });

    const { status } = await httpGet(url);
    expect(status).toBe(403);

    ws.terminate();
  });

  it("unknown provider → 404", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const url = await buildAuthUrl(httpPort, daemon.identity, "notarealProvider", sessionId);

    const { status } = await httpGet(url);
    expect(status).toBe(404);

    ws.terminate();
  });

  it("missing session param → 400", async () => {
    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?challenge=x&relay_uuid=${"a".repeat(64)}&sig=x&timestamp=1`;
    const { status } = await httpGet(url);
    expect(status).toBe(400);
  });

  it("invalid relay_uuid format (not 64 hex) → 400", async () => {
    const ts = Math.floor(Date.now() / 1000).toString();
    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=550e8400-e29b-41d4-a716-446655440000` +
      `&challenge=abc` +
      `&relay_uuid=notvalidhex` +
      `&sig=abc` +
      `&timestamp=${ts}`;

    const { status } = await httpGet(url);
    expect(status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Callback route tests
// ---------------------------------------------------------------------------

describe("Broker /callback/:provider", () => {
  let fixture: MtlsRelayFixture;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    sessions = new SessionStore(testSessionTtlMs);

    const app = express();
    app.use(buildBrokerRouter(fixture.relay, sessions, testProviders()));

    await new Promise<void>((resolve) => {
      httpServer = app.listen(0, () => {
        resolve();
      });
    });

    const addr = httpServer.address();
    if (addr === null || typeof addr === "string") throw new Error("No port");
    httpPort = addr.port;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => {
        if (err !== undefined) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
    await fixture.close();
    sessions.clear();
  });

  it("missing state → 400", async () => {
    const url = `http://localhost:${httpPort.toString()}/callback/github?access_token=tok`;
    const resp = await fetch(url);
    expect(resp.status).toBe(400);
  });

  it("missing access_token → 400", async () => {
    const url = `http://localhost:${httpPort.toString()}/callback/github?state=session-id`;
    const resp = await fetch(url);
    expect(resp.status).toBe(400);
  });

  it("error param present → 400", async () => {
    const url = `http://localhost:${httpPort.toString()}/callback/github?error=access_denied`;
    const resp = await fetch(url);
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("access_denied");
  });

  it("session not found → 400", async () => {
    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=nonexistent-session&access_token=tok`;
    const resp = await fetch(url);
    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain("Session expired");
  });

  it("valid callback with connected daemon → 200", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440001";

    // Store a session pointing to the connected daemon. The ECIES recipient
    // is the daemon's decrypt pubkey (v4 split identity).
    const session: Session = {
      sessionId,
      relayUuid: daemon.identity.uuid,
      pubkey: Buffer.from(daemon.identity.decryptPubkeyB64, "base64"),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    sessions.set(session);

    // Set up the daemon to respond to forwarded requests
    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req !== null) {
        ws.send(
          responseEnvelope({
            id: req.id,
            status: 200,
            body: Buffer.from("{}").toString("base64"),
          }),
        );
      }
    });

    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=${encodeURIComponent(sessionId)}&access_token=tok_abc123`;

    const resp = await fetch(url);
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain("Authorization complete");

    // Session should be deleted after delivery
    expect(sessions.get(sessionId)).toBeUndefined();

    ws.terminate();
  });

  it("callback with daemon not connected → 503", async () => {
    const sessionId = "550e8400-e29b-41d4-a716-446655440002";

    // Store a session pointing to a non-connected daemon
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const session: Session = {
      sessionId,
      relayUuid: "a".repeat(64), // not connected
      pubkey: daemonECDH.getPublicKey(),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    sessions.set(session);

    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=${encodeURIComponent(sessionId)}&access_token=tok_abc123`;

    const resp = await fetch(url);
    expect(resp.status).toBe(503);
    const body = await resp.text();
    expect(body).toContain("retry");
  });
});
