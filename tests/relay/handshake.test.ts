/**
 * Relay handshake tests — real crypto, real in-process WebSocket connections.
 * No mocks.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { RelayServer } from "../../src/relay/server.js";
import { NonceStore } from "../../src/relay/nonces.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateSigningIdentity(): {
  uuid: string;
  pubkeyBase64: string;
  sign: (message: Buffer) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const spki = publicKey as Buffer;
  const pubkeyBytes = spki.subarray(spki.length - 65);

  const uuid = createHash("sha256").update(pubkeyBytes).digest("hex");

  const sign = (message: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(message);
    return signer.sign(privateKey, "base64");
  };

  return { uuid, pubkeyBase64: pubkeyBytes.toString("base64"), sign };
}

function buildHelloPayload(nonce: string, timestamp: number): Buffer {
  const nonceBytes = Buffer.from(nonce, "hex");
  const tsBytes = Buffer.allocUnsafe(8);
  tsBytes.writeBigUInt64BE(BigInt(timestamp));
  return createHash("sha256").update(nonceBytes).update(tsBytes).digest();
}

/** Connect a WebSocket client and return the first message (the challenge). */
function connectAndGetChallenge(port: number): Promise<{ ws: WebSocket; nonce: string }> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${port.toString()}`);
    ws.once("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        type: string;
        nonce: string;
      };
      if (msg.type !== "challenge") {
        reject(new Error(`Expected challenge, got: ${msg.type}`));
        return;
      }
      resolve({ ws, nonce: msg.nonce });
    });
    ws.once("error", reject);
  });
}

/** Send a hello message and wait for the next message (welcome or error). */
function sendHelloAndWait(
  ws: WebSocket,
  hello: object,
): Promise<{ type: string; message?: string; url?: string }> {
  return new Promise((resolve, reject) => {
    ws.send(JSON.stringify(hello));
    ws.once("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        type: string;
        message?: string;
        url?: string;
      };
      resolve(msg);
    });
    ws.once("error", reject);
  });
}

/** Wait for the WebSocket to close. */
function waitForClose(ws: WebSocket): Promise<void> {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.CLOSED) {
      resolve();
      return;
    }
    ws.once("close", () => {
      resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Relay handshake", () => {
  let server: RelayServer;
  let port: number;

  beforeEach(() => {
    server = new RelayServer({ baseUrl: "wss://relay.dicode.app" });
    port = server.port;
  });

  afterEach(async () => {
    await server.close();
  });

  it("valid handshake: client connects, receives welcome", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000);
    const payload = buildHelloPayload(nonce, timestamp);
    const sig = identity.sign(payload);

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(response.type).toBe("welcome");
    expect(response.url).toBe(`wss://relay.dicode.app/u/${identity.uuid}/hooks/`);
    expect(server.hasClient(identity.uuid)).toBe(true);

    ws.close();
    await waitForClose(ws);
  });

  it("wrong pubkey: uuid does not match sha256(pubkey) → error + close", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000);
    const payload = buildHelloPayload(nonce, timestamp);
    const sig = identity.sign(payload);

    // Use wrong UUID (all zeros)
    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: "0".repeat(64),
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    await waitForClose(ws);
  });

  it("stale timestamp (>30 s old) → error + close", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000) - 60; // 60 seconds ago
    const payload = buildHelloPayload(nonce, timestamp);
    const sig = identity.sign(payload);

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    await waitForClose(ws);
  });

  it("replayed nonce: NonceStore rejects duplicate nonces", () => {
    const store = new NonceStore();
    const nonce = randomBytes(32).toString("hex");

    // First check: not seen yet → registers and returns false
    expect(store.check(nonce)).toBe(false);
    // Second check: already seen → returns true
    expect(store.check(nonce)).toBe(true);

    store.clear();
  });

  it("connection cleanup: client disconnects → registry entry removed", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000);
    const payload = buildHelloPayload(nonce, timestamp);
    const sig = identity.sign(payload);

    await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(server.hasClient(identity.uuid)).toBe(true);

    ws.close();
    await waitForClose(ws);

    // Give the server a tick to process the close event
    await new Promise((r) => setTimeout(r, 50));
    expect(server.hasClient(identity.uuid)).toBe(false);
  });

  it("invalid JSON → connection closed", async () => {
    const { ws } = await connectAndGetChallenge(port);

    const closed = waitForClose(ws);
    ws.send("not json");
    await closed;
  });

  it("invalid pubkey length → error + close", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000);
    const payload = buildHelloPayload(nonce, timestamp);
    const sig = identity.sign(payload);

    // Send only 32 bytes of pubkey
    const shortPubkey = randomBytes(32).toString("base64");
    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: shortPubkey,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    await waitForClose(ws);
  });

  it("bad signature → error + close", async () => {
    const identity = generateSigningIdentity();
    const { ws } = await connectAndGetChallenge(port);

    const timestamp = Math.floor(Date.now() / 1000);
    // Sign with wrong message to produce wrong signature
    const wrongPayload = randomBytes(32);
    const sig = identity.sign(wrongPayload);

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    await waitForClose(ws);
  });
});

describe("NonceStore", () => {
  it("check returns false first time, true second time for same nonce", () => {
    const store = new NonceStore();
    const nonce = randomBytes(32).toString("hex");

    expect(store.check(nonce)).toBe(false);
    expect(store.check(nonce)).toBe(true);
    expect(store.size).toBe(1);
  });

  it("different nonces are tracked independently", () => {
    const store = new NonceStore();
    const n1 = randomBytes(32).toString("hex");
    const n2 = randomBytes(32).toString("hex");

    expect(store.check(n1)).toBe(false);
    expect(store.check(n2)).toBe(false);
    expect(store.check(n1)).toBe(true);
    expect(store.check(n2)).toBe(true);
    expect(store.size).toBe(2);

    store.clear();
    expect(store.size).toBe(0);
  });
});
