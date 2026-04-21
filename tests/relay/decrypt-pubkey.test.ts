/**
 * Handshake tests for the optional decrypt_pubkey field (dicode-core#104 /
 * dicode-relay#28). Real crypto, real in-process WebSocket connections.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { PROTOCOL_VERSION, RelayServer } from "../../src/relay/server.js";
import { testRelayOpts } from "../helpers.js";

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

function sendHelloAndWait(
  ws: WebSocket,
  hello: object,
): Promise<{ type: string; message?: string; url?: string; protocol?: number }> {
  return new Promise((resolve, reject) => {
    ws.send(JSON.stringify(hello));
    ws.once("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        type: string;
        message?: string;
        url?: string;
        protocol?: number;
      };
      resolve(msg);
    });
    ws.once("error", reject);
  });
}

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

describe("Relay handshake — decrypt_pubkey + protocol v2", () => {
  let server: RelayServer;
  let port: number;

  beforeEach(() => {
    server = new RelayServer(testRelayOpts({ baseUrl: "wss://relay.dicode.app" }));
    port = server.port;
  });

  afterEach(async () => {
    await server.close();
  });

  it("welcome always announces protocol: 2", async () => {
    const identity = generateSigningIdentity();
    const decryptPubkey = generateDecryptPubkey();
    const { ws, nonce } = await connectAndGetChallenge(port);
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = identity.sign(buildHelloPayload(nonce, timestamp));

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      decrypt_pubkey: decryptPubkey.toString("base64"),
      sig,
      timestamp,
    });

    expect(response.type).toBe("welcome");
    expect(response.protocol).toBe(PROTOCOL_VERSION);
    expect(response.protocol).toBe(2);

    ws.close();
    await waitForClose(ws);
  });

  it("valid decrypt_pubkey: stored on ConnectedClient and distinct from pubkey", async () => {
    const identity = generateSigningIdentity();
    const decryptPubkey = generateDecryptPubkey();
    const { ws, nonce } = await connectAndGetChallenge(port);
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = identity.sign(buildHelloPayload(nonce, timestamp));

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      decrypt_pubkey: decryptPubkey.toString("base64"),
      sig,
      timestamp,
    });

    expect(response.type).toBe("welcome");

    const client = server.getClient(identity.uuid);
    expect(client.pubkey.equals(identity.pubkeyBytes)).toBe(true);
    expect(client.decryptPubkey.equals(decryptPubkey)).toBe(true);
    expect(client.decryptPubkey.equals(client.pubkey)).toBe(false);

    ws.close();
    await waitForClose(ws);
  });

  it("missing decrypt_pubkey: handshake rejected (required field)", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = identity.sign(buildHelloPayload(nonce, timestamp));

    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    expect(server.hasClient(identity.uuid)).toBe(false);

    await waitForClose(ws);
  });

  it("decrypt_pubkey wrong length: handshake rejected with clear error", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = identity.sign(buildHelloPayload(nonce, timestamp));

    const shortDecryptPubkey = randomBytes(32).toString("base64");
    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      decrypt_pubkey: shortDecryptPubkey,
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    expect(response.message).toContain("decrypt_pubkey");
    expect(server.hasClient(identity.uuid)).toBe(false);

    await waitForClose(ws);
  });

  it("decrypt_pubkey not on curve: handshake rejected", async () => {
    const identity = generateSigningIdentity();
    const { ws, nonce } = await connectAndGetChallenge(port);
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = identity.sign(buildHelloPayload(nonce, timestamp));

    // 0x04 prefix + 64 bytes of zeros — structurally valid (length + prefix)
    // but not a point on P-256. createPublicKey must reject this.
    const offCurve = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0x00)]);
    const response = await sendHelloAndWait(ws, {
      type: "hello",
      uuid: identity.uuid,
      pubkey: identity.pubkeyBase64,
      decrypt_pubkey: offCurve.toString("base64"),
      sig,
      timestamp,
    });

    expect(response.type).toBe("error");
    expect(response.message).toContain("decrypt_pubkey");
    expect(server.hasClient(identity.uuid)).toBe(false);

    await waitForClose(ws);
  });
});
