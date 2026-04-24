/**
 * Broker session pubkey selection (dicode-core#104 / dicode-relay#28).
 * When a daemon advertises decrypt_pubkey on hello, the OAuth session's
 * ECIES recipient must be the decrypt pubkey, not the sign pubkey.
 * When no decrypt_pubkey is advertised (pre-v2 daemon), the session falls
 * back to the sign pubkey.
 */

import type { Server } from "node:http";
import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { buildBrokerRouter } from "../../src/broker/router.js";
import { buildSignedPayload } from "../../src/broker/crypto.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SessionStore } from "../../src/broker/sessions.js";
import { RelayServer } from "../../src/relay/server.js";
import {
  helloEnvelope,
  parseChallenge,
  parseWelcome,
  testRelayOpts,
  testSessionTtlMs,
} from "../helpers.js";

function testProviders(): ReadonlyMap<string, ProviderConfig> {
  return new Map([
    [
      "github",
      { grantKey: "github", clientId: "test-client-id", pkce: true, scopes: ["user", "repo"] },
    ],
  ]);
}

interface SignIdentity {
  uuid: string;
  pubkeyBase64: string;
  pubkeyBytes: Buffer;
  sign: (message: Buffer) => string;
}

function generateSigningIdentity(): SignIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const spki = publicKey as Buffer;
  const pubkeyBytes = Buffer.from(spki.subarray(spki.length - 65));
  const uuid = createHash("sha256").update(pubkeyBytes).digest("hex");
  const sign = (message: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(message);
    return signer.sign(privateKey, "base64");
  };
  return { uuid, pubkeyBase64: pubkeyBytes.toString("base64"), pubkeyBytes, sign };
}

function generateDecryptPubkey(): Buffer {
  const { publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const spki = publicKey as Buffer;
  return Buffer.from(spki.subarray(spki.length - 65));
}

function buildHelloPayload(nonce: string, timestamp: number): Buffer {
  const nonceBytes = Buffer.from(nonce, "hex");
  const tsBytes = Buffer.allocUnsafe(8);
  tsBytes.writeBigUInt64BE(BigInt(timestamp));
  return Buffer.concat([nonceBytes, tsBytes]);
}

function connectDaemon(
  relayPort: number,
  identity: SignIdentity,
  decryptPubkey: Buffer,
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${relayPort.toString()}`);
    ws.once("message", (data: Buffer | string) => {
      const challenge = parseChallenge(data);
      if (challenge === null) {
        reject(new Error("Expected challenge envelope"));
        return;
      }
      const timestamp = Math.floor(Date.now() / 1000);
      const sig = identity.sign(buildHelloPayload(challenge.nonce, timestamp));

      ws.send(
        helloEnvelope({
          uuid: identity.uuid,
          pubkey: identity.pubkeyBase64,
          decrypt_pubkey: decryptPubkey.toString("base64"),
          sig,
          timestamp,
        }),
      );

      ws.once("message", (data2: Buffer | string) => {
        if (parseWelcome(data2) !== null) {
          resolve(ws);
        } else {
          reject(new Error(`Expected welcome envelope, got: ${data2.toString()}`));
        }
      });
    });
    ws.once("error", reject);
  });
}

async function startAuth(
  httpPort: number,
  identity: SignIdentity,
  sessionId: string,
): Promise<Response> {
  const pkceChallenge = randomBytes(32).toString("base64url");
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = buildSignedPayload(sessionId, pkceChallenge, identity.uuid, "github", timestamp);
  const sig = identity.sign(payload);

  const url =
    `http://localhost:${httpPort.toString()}/auth/github` +
    `?session=${encodeURIComponent(sessionId)}` +
    `&challenge=${encodeURIComponent(pkceChallenge)}` +
    `&relay_uuid=${identity.uuid}` +
    `&sig=${encodeURIComponent(sig)}` +
    `&timestamp=${timestamp.toString()}`;
  return fetch(url, { redirect: "manual" });
}

describe("Broker ECIES recipient selection", () => {
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

  it("session.pubkey = decryptPubkey, distinct from sign pubkey", async () => {
    const identity = generateSigningIdentity();
    const decryptPubkey = generateDecryptPubkey();
    const ws = await connectDaemon(relayServer.port, identity, decryptPubkey);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const response = await startAuth(httpPort, identity, sessionId);
    expect(response.status).toBe(302);

    const stored = sessions.get(sessionId);
    expect(stored).toBeDefined();
    expect(stored?.pubkey.equals(decryptPubkey)).toBe(true);
    expect(stored?.pubkey.equals(identity.pubkeyBytes)).toBe(false);

    ws.close();
  });
});
