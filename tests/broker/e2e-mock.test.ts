/**
 * E2E mock provider tests — real crypto, in-process RelayServer, no mocks.
 *
 * Covers:
 *  - GET /connect/mock — short-circuit redirect to /callback/mock
 *  - POST /_test/deliver — low-level wire-shape primitive
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { buildE2EMockRouter, MOCK_PROVIDER_KEY } from "../../src/broker/e2e-mock.js";
import { SessionStore } from "../../src/broker/sessions.js";
import { verifyDeliverySignature } from "../../src/broker/signing.js";
import type { BrokerSigningKey } from "../../src/broker/signing.js";
import { loadBrokerSigningKey } from "../../src/broker/signing.js";
import { RelayServer } from "../../src/relay/server.js";
import type { RequestMessage, ResponseMessage } from "../../src/relay/protocol.js";
import { testRelayOpts, testSessionTtlMs } from "../helpers.js";

const BASE_URL = "https://relay.test.local";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function generateSigningIdentity(): {
  uuid: string;
  pubkeyBase64: string;
  decryptPubkeyBase64: string;
  decryptPubkeyBytes: Buffer;
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

  const { publicKey: decryptPublicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const decryptSpki = decryptPublicKey as Buffer;
  const decryptPubkeyBytes = Buffer.from(decryptSpki.subarray(decryptSpki.length - 65));

  const sign = (payload: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(payload);
    return signer.sign(privateKey, "base64");
  };

  return {
    uuid,
    pubkeyBase64: pubkeyBytes.toString("base64"),
    decryptPubkeyBase64: decryptPubkeyBytes.toString("base64"),
    decryptPubkeyBytes,
    sign,
  };
}

function buildHelloPayload(nonce: string, timestamp: number): Buffer {
  const nonceBytes = Buffer.from(nonce, "hex");
  const tsBytes = Buffer.allocUnsafe(8);
  tsBytes.writeBigUInt64BE(BigInt(timestamp));
  return Buffer.concat([nonceBytes, tsBytes]);
}

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
          decrypt_pubkey: identity.decryptPubkeyBase64,
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

describe("E2E mock router", () => {
  let relayServer: RelayServer;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;
  let brokerKey: BrokerSigningKey;

  beforeEach(async () => {
    relayServer = new RelayServer(testRelayOpts({ baseUrl: "wss://relay.test.local" }));
    sessions = new SessionStore(testSessionTtlMs);
    // Use an inline PEM so tests do not touch disk.
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    brokerKey = loadBrokerSigningKey({ BROKER_SIGNING_KEY: pair.privateKey }, "/tmp");

    const app = express();
    app.use(buildE2EMockRouter(relayServer, sessions, brokerKey, BASE_URL));

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

  // -------------------------------------------------------------------------
  // /connect/mock
  // -------------------------------------------------------------------------

  describe("GET /connect/mock", () => {
    it("valid session → 302 redirect to /callback/mock with synthetic token", async () => {
      const sessionId = "550e8400-e29b-41d4-a716-446655440000";
      const identity = generateSigningIdentity();
      sessions.set({
        sessionId,
        relayUuid: identity.uuid,
        pubkey: identity.decryptPubkeyBytes,
        pkceChallenge: "challenge",
        provider: MOCK_PROVIDER_KEY,
        expiresAt: Date.now() + 60_000,
      });

      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=${sessionId}`,
        { redirect: "manual" },
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("location");
      expect(location).not.toBeNull();
      const url = new URL(location ?? "");
      expect(url.origin + url.pathname).toBe(`${BASE_URL}/callback/mock`);
      expect(url.searchParams.get("state")).toBe(sessionId);
      expect(url.searchParams.get("access_token")).toBe(`mock-token-${sessionId}`);
      expect(url.searchParams.get("token_type")).toBe("bearer");
    });

    it("missing state → 400", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/connect/mock`);
      expect(response.status).toBe(400);
    });

    it("unknown state → 400", async () => {
      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=does-not-exist`,
      );
      expect(response.status).toBe(400);
    });

    it("session for a non-mock provider → 400", async () => {
      const sessionId = "aa0e8400-e29b-41d4-a716-446655440000";
      const identity = generateSigningIdentity();
      sessions.set({
        sessionId,
        relayUuid: identity.uuid,
        pubkey: identity.decryptPubkeyBytes,
        pkceChallenge: "challenge",
        provider: "github",
        expiresAt: Date.now() + 60_000,
      });

      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=${sessionId}`,
      );
      expect(response.status).toBe(400);
    });
  });

  // -------------------------------------------------------------------------
  // /_test/deliver
  // -------------------------------------------------------------------------

  describe("POST /_test/deliver", () => {
    it("missing fields → 400", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uuid: "x" }),
      });
      expect(response.status).toBe(400);
    });

    it("unknown daemon uuid → 404", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: "a".repeat(64),
          session_id: randomBytes(16).toString("hex"),
          provider: "github",
          tokens: { access_token: "t" },
        }),
      });
      expect(response.status).toBe(404);
    });

    it("connected daemon → encrypts + signs + forwards; daemon can verify sig", async () => {
      const identity = generateSigningIdentity();
      const ws = await connectDaemon(relayServer.port, identity);

      // Capture the request message that arrives at the daemon end.
      const forwarded: RequestMessage[] = [];
      ws.on("message", (data: Buffer | string) => {
        const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
          string,
          unknown
        >;
        if (msg.type === "request") {
          forwarded.push(msg as unknown as RequestMessage);
          const req = msg as RequestMessage;
          const response: ResponseMessage = {
            type: "response",
            id: req.id,
            status: 200,
            headers: {},
            body: Buffer.from("ok").toString("base64"),
          };
          ws.send(JSON.stringify(response));
        }
      });

      const sessionId = randomBytes(16).toString("hex");
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: identity.uuid,
          session_id: sessionId,
          provider: "github",
          tokens: { access_token: "test-token" },
        }),
      });

      expect(response.status).toBe(200);
      expect(forwarded).toHaveLength(1);
      expect(forwarded[0]?.path).toBe("/hooks/oauth-complete");

      const bodyJson = JSON.parse(
        Buffer.from(forwarded[0]?.body ?? "", "base64").toString("utf8"),
      ) as {
        type: string;
        session_id: string;
        ephemeral_pubkey: string;
        ciphertext: string;
        nonce: string;
        broker_sig: string;
      };
      expect(bodyJson.type).toBe("oauth_token_delivery");
      expect(bodyJson.session_id).toBe(sessionId);
      expect(
        verifyDeliverySignature(
          brokerKey.publicKeyBase64,
          bodyJson.broker_sig,
          bodyJson.type,
          bodyJson.session_id,
          bodyJson.ephemeral_pubkey,
          bodyJson.ciphertext,
          bodyJson.nonce,
        ),
      ).toBe(true);

      ws.close();
    });
  });
});
