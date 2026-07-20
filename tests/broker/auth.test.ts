/**
 * Broker auth route tests — real crypto, in-process mTLS RelayServer, no mocks.
 */

import { randomBytes, createECDH } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildBrokerRouter } from "../../src/broker/router.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SeenSet, type Session } from "../../src/broker/sessions.js";
import type { BrokerSigningKey } from "../../src/shared/signing.js";
import { Identity } from "../../src/client/identity.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseRequest,
  responseEnvelope,
  testSessionTtlMs,
  testBrokerKey,
  mountFlowSession,
  decodeFlowCookie,
  flowCookieHeader,
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
  let seen: SeenSet;
  let brokerKey: BrokerSigningKey;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    seen = new SeenSet(testSessionTtlMs);
    brokerKey = testBrokerKey();

    const app = express();
    mountFlowSession(app, brokerKey);
    app.use(buildBrokerRouter(fixture.relay, seen, testProviders(), 30, brokerKey));

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
    seen.clear();
  });

  it("valid request with correct sig → 302 redirect to Grant, flow sealed in cookie", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const url = await buildAuthUrl(httpPort, daemon.identity, "github", sessionId);
    const response = await fetch(url, { redirect: "manual" });

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).toContain("/connect/github");

    // Flow state is sealed into the browser cookie (no in-process store).
    const flow = decodeFlowCookie(response, brokerKey);
    expect(flow).not.toBeNull();
    expect(flow?.sessionId).toBe(sessionId);
    expect(flow?.provider).toBe("github");
    expect(flow?.relayUuid).toBe(daemon.identity.uuid);

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
  let seen: SeenSet;
  let brokerKey: BrokerSigningKey;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    seen = new SeenSet(testSessionTtlMs);
    brokerKey = testBrokerKey();

    const app = express();
    mountFlowSession(app, brokerKey);
    app.use(buildBrokerRouter(fixture.relay, seen, testProviders(), 30, brokerKey));

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
    seen.clear();
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

    // Flow state pointing to the connected daemon, carried in the cookie. The
    // ECIES recipient is the daemon's decrypt pubkey (v4 split identity).
    const session: Session = {
      sessionId,
      relayUuid: daemon.identity.uuid,
      pubkey: Buffer.from(daemon.identity.decryptPubkeyB64, "base64"),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    const cookie = await flowCookieHeader(brokerKey, session);

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

    const resp = await fetch(url, { headers: { cookie } });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain("Authorization complete");

    // Session id is now recorded as consumed (single-use).
    expect(seen.has(sessionId)).toBe(true);

    ws.terminate();
  });

  it("replaying the same callback cookie → 400 (single-use)", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440003";
    const session: Session = {
      sessionId,
      relayUuid: daemon.identity.uuid,
      pubkey: Buffer.from(daemon.identity.decryptPubkeyB64, "base64"),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    const cookie = await flowCookieHeader(brokerKey, session);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req !== null) {
        ws.send(
          responseEnvelope({ id: req.id, status: 200, body: Buffer.from("{}").toString("base64") }),
        );
      }
    });

    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=${encodeURIComponent(sessionId)}&access_token=tok_abc123`;

    const first = await fetch(url, { headers: { cookie } });
    expect(first.status).toBe(200);

    // Same sealed cookie again — the per-instance seen-set rejects the replay.
    const second = await fetch(url, { headers: { cookie } });
    expect(second.status).toBe(400);
    expect(await second.text()).toContain("already used");

    ws.terminate();
  });

  it("callback state not matching the sealed session id → 400", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440004";
    const session: Session = {
      sessionId,
      relayUuid: daemon.identity.uuid,
      pubkey: Buffer.from(daemon.identity.decryptPubkeyB64, "base64"),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    const cookie = await flowCookieHeader(brokerKey, session);

    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=a-different-state&access_token=tok_abc123`;

    const resp = await fetch(url, { headers: { cookie } });
    expect(resp.status).toBe(400);
    expect(await resp.text()).toContain("mismatch");

    ws.terminate();
  });

  it("callback with daemon not connected → 503", async () => {
    const sessionId = "550e8400-e29b-41d4-a716-446655440002";

    // Flow state pointing to a non-connected daemon.
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
    const cookie = await flowCookieHeader(brokerKey, session);

    const url =
      `http://localhost:${httpPort.toString()}/callback/github` +
      `?state=${encodeURIComponent(sessionId)}&access_token=tok_abc123`;

    const resp = await fetch(url, { headers: { cookie } });
    expect(resp.status).toBe(503);
    const body = await resp.text();
    expect(body).toContain("retry");
  });

  it("callback landing on a fresh instance (same broker key) still delivers → LB-safe", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    // Instance B: a brand-new router + seen-set sharing only the broker key
    // (as every instance behind a load balancer derives the same flow key).
    const appB = express();
    mountFlowSession(appB, brokerKey);
    appB.use(
      buildBrokerRouter(
        fixture.relay,
        new SeenSet(testSessionTtlMs),
        testProviders(),
        30,
        brokerKey,
      ),
    );
    const serverB = await new Promise<Server>((resolve) => {
      const s = appB.listen(0, () => {
        resolve(s);
      });
    });
    const portB = (serverB.address() as { port: number }).port;

    const sessionId = "550e8400-e29b-41d4-a716-446655440005";
    const session: Session = {
      sessionId,
      relayUuid: daemon.identity.uuid,
      pubkey: Buffer.from(daemon.identity.decryptPubkeyB64, "base64"),
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    // Cookie minted as if by instance A; presented to instance B.
    const cookie = await flowCookieHeader(brokerKey, session);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req !== null) {
        ws.send(
          responseEnvelope({ id: req.id, status: 200, body: Buffer.from("{}").toString("base64") }),
        );
      }
    });

    const resp = await fetch(
      `http://localhost:${portB.toString()}/callback/github` +
        `?state=${encodeURIComponent(sessionId)}&access_token=tok_abc123`,
      { headers: { cookie } },
    );
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain("Authorization complete");

    await new Promise<void>((resolve) => {
      serverB.close(() => {
        resolve();
      });
    });
    ws.terminate();
  });
});
