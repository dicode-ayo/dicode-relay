/**
 * Broker auth route tests — real crypto, in-process RelayServer, no mocks.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { buildBrokerRouter } from "../../src/broker/router.js";
import { buildSignedPayload } from "../../src/broker/crypto.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SessionStore } from "../../src/broker/sessions.js";
import { RelayServer } from "../../src/relay/server.js";
import { testSessionTtlMs, testRelayOpts } from "../helpers.js";

/** Test provider map with a single "github" provider. */
function testProviders(): ReadonlyMap<string, ProviderConfig> {
  return new Map([
    [
      "github",
      { grantKey: "github", clientId: "test-client-id", pkce: true, scopes: ["user", "repo"] },
    ],
  ]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateSigningIdentity(): {
  uuid: string;
  pubkeyBase64: string;
  pubkeyBytes: Buffer;
  sign: (payload: Buffer) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const spki = publicKey as Buffer;
  const pubkeyBytes = Buffer.from(spki.subarray(spki.length - 65));
  const uuid = createHash("sha256").update(pubkeyBytes).digest("hex");

  const sign = (payload: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(payload);
    return signer.sign(privateKey, "base64");
  };

  return { uuid, pubkeyBase64: pubkeyBytes.toString("base64"), pubkeyBytes, sign };
}

function buildHelloPayload(nonce: string, timestamp: number): Buffer {
  const nonceBytes = Buffer.from(nonce, "hex");
  const tsBytes = Buffer.allocUnsafe(8);
  tsBytes.writeBigUInt64BE(BigInt(timestamp));
  return Buffer.concat([nonceBytes, tsBytes]);
}

/** Perform full relay handshake for a given identity, return connected ws */
async function connectDaemon(
  relayPort: number,
  identity: ReturnType<typeof generateSigningIdentity>,
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${relayPort.toString()}`);
    ws.once("message", (data: Buffer | string) => {
      const challenge = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        nonce: string;
      };
      const timestamp = Math.floor(Date.now() / 1000);
      const payload = buildHelloPayload(challenge.nonce, timestamp);
      const sig = identity.sign(payload);

      ws.send(
        JSON.stringify({
          type: "hello",
          uuid: identity.uuid,
          pubkey: identity.pubkeyBase64,
          sig,
          timestamp,
        }),
      );

      ws.once("message", (data2: Buffer | string) => {
        const welcome = JSON.parse(typeof data2 === "string" ? data2 : data2.toString()) as {
          type: string;
        };
        if (welcome.type === "welcome") {
          resolve(ws);
        } else {
          reject(new Error(`Expected welcome, got ${welcome.type}`));
        }
      });
    });
    ws.once("error", reject);
  });
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
  let relayServer: RelayServer;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;

  beforeEach(async () => {
    relayServer = new RelayServer(testRelayOpts({ baseUrl: "wss://relay.dicode.app" }));
    sessions = new SessionStore(testSessionTtlMs);

    const app = express();
    app.use(buildBrokerRouter(relayServer, sessions, testProviders()));

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
    await relayServer.close();
    sessions.clear();
  });

  it("valid request with correct sig → 302 redirect to Grant", async () => {
    const identity = generateSigningIdentity();
    const daemonWs = await connectDaemon(relayServer.port, identity);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const timestamp = Math.floor(Date.now() / 1000);

    const payload = buildSignedPayload(
      sessionId,
      pkceChallenge,
      identity.uuid,
      "github",
      timestamp,
    );
    const sig = identity.sign(payload);

    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(pkceChallenge)}` +
      `&relay_uuid=${identity.uuid}` +
      `&sig=${encodeURIComponent(sig)}` +
      `&timestamp=${timestamp.toString()}`;

    const response = await fetch(url, { redirect: "manual" });

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).toContain("/connect/github");

    // Session should be stored
    expect(sessions.get(sessionId)).toBeDefined();
    expect(sessions.get(sessionId)?.provider).toBe("github");

    daemonWs.close();
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
    const identity = generateSigningIdentity();
    // Do NOT connect this identity to relay

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const timestamp = Math.floor(Date.now() / 1000);

    const payload = buildSignedPayload(
      sessionId,
      pkceChallenge,
      identity.uuid,
      "github",
      timestamp,
    );
    const sig = identity.sign(payload);

    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(pkceChallenge)}` +
      `&relay_uuid=${identity.uuid}` +
      `&sig=${encodeURIComponent(sig)}` +
      `&timestamp=${timestamp.toString()}`;

    const { status } = await httpGet(url);
    expect(status).toBe(403);
  });

  it("bad ECDSA signature → 403", async () => {
    const identity = generateSigningIdentity();
    const daemonWs = await connectDaemon(relayServer.port, identity);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const timestamp = Math.floor(Date.now() / 1000);

    // Use a random (invalid) signature
    const badSig = randomBytes(64).toString("base64");

    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(pkceChallenge)}` +
      `&relay_uuid=${identity.uuid}` +
      `&sig=${encodeURIComponent(badSig)}` +
      `&timestamp=${timestamp.toString()}`;

    const { status } = await httpGet(url);
    expect(status).toBe(403);

    daemonWs.close();
  });

  it("stale timestamp → 403", async () => {
    const identity = generateSigningIdentity();
    const daemonWs = await connectDaemon(relayServer.port, identity);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const timestamp = Math.floor(Date.now() / 1000) - 60; // 60 seconds ago

    const payload = buildSignedPayload(
      sessionId,
      pkceChallenge,
      identity.uuid,
      "github",
      timestamp,
    );
    const sig = identity.sign(payload);

    const url =
      `http://localhost:${httpPort.toString()}/auth/github` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(pkceChallenge)}` +
      `&relay_uuid=${identity.uuid}` +
      `&sig=${encodeURIComponent(sig)}` +
      `&timestamp=${timestamp.toString()}`;

    const { status } = await httpGet(url);
    expect(status).toBe(403);

    daemonWs.close();
  });

  it("unknown provider → 404", async () => {
    const identity = generateSigningIdentity();
    const daemonWs = await connectDaemon(relayServer.port, identity);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const timestamp = Math.floor(Date.now() / 1000);

    const payload = buildSignedPayload(
      sessionId,
      pkceChallenge,
      identity.uuid,
      "notarealProvider",
      timestamp,
    );
    const sig = identity.sign(payload);

    const url =
      `http://localhost:${httpPort.toString()}/auth/notarealProvider` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(pkceChallenge)}` +
      `&relay_uuid=${identity.uuid}` +
      `&sig=${encodeURIComponent(sig)}` +
      `&timestamp=${timestamp.toString()}`;

    const { status } = await httpGet(url);
    expect(status).toBe(404);

    daemonWs.close();
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

import { createECDH } from "node:crypto";
import type { Session } from "../../src/broker/sessions.js";

describe("Broker /callback/:provider", () => {
  let relayServer: RelayServer;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;

  beforeEach(async () => {
    relayServer = new RelayServer(testRelayOpts({ baseUrl: "wss://relay.dicode.app" }));
    sessions = new SessionStore(testSessionTtlMs);

    const app = express();
    app.use(buildBrokerRouter(relayServer, sessions, testProviders()));

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
    await relayServer.close();
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
    const identity = generateSigningIdentity();
    const daemonWs = await connectDaemon(relayServer.port, identity);

    const sessionId = "550e8400-e29b-41d4-a716-446655440001";

    // Store a session pointing to the connected daemon
    const session: Session = {
      sessionId,
      relayUuid: identity.uuid,
      pubkey: identity.pubkeyBytes,
      pkceChallenge: randomBytes(32).toString("base64url"),
      provider: "github",
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    sessions.set(session);

    // Set up the daemon to respond to forwarded requests
    daemonWs.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        type: string;
        id: string;
      };
      if (msg.type === "request") {
        daemonWs.send(
          JSON.stringify({
            type: "response",
            id: msg.id,
            status: 200,
            headers: {},
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

    daemonWs.close();
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
