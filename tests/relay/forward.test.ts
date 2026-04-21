/**
 * Relay forwarding tests — in-process WebSocket connections, no mocks.
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import {
  ClientNotConnectedError,
  ForwardTimeoutError,
  RelayServer,
} from "../../src/relay/server.js";
import type { RequestMessage, ResponseMessage } from "../../src/relay/protocol.js";
import { testRelayOpts } from "../helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateSigningIdentity(): {
  uuid: string;
  pubkeyBase64: string;
  decryptPubkeyBase64: string;
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

  const { publicKey: decryptPublicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const decryptSpki = decryptPublicKey as Buffer;
  const decryptPubkeyBytes = decryptSpki.subarray(decryptSpki.length - 65);

  const sign = (message: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(message);
    return signer.sign(privateKey, "base64");
  };

  return {
    uuid,
    pubkeyBase64: pubkeyBytes.toString("base64"),
    decryptPubkeyBase64: decryptPubkeyBytes.toString("base64"),
    sign,
  };
}

function buildHelloPayload(nonce: string, timestamp: number): Buffer {
  const nonceBytes = Buffer.from(nonce, "hex");
  const tsBytes = Buffer.allocUnsafe(8);
  tsBytes.writeBigUInt64BE(BigInt(timestamp));
  return Buffer.concat([nonceBytes, tsBytes]);
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

/**
 * Perform a full handshake and return the connected WebSocket.
 */
async function performHandshake(port: number): Promise<{ ws: WebSocket; uuid: string }> {
  const identity = generateSigningIdentity();

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${port.toString()}`);

    ws.once("message", (data: Buffer | string) => {
      const challenge = JSON.parse(typeof data === "string" ? data : data.toString()) as {
        type: string;
        nonce: string;
      };
      if (challenge.type !== "challenge") {
        reject(new Error("Expected challenge"));
        return;
      }

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
        if (welcome.type !== "welcome") {
          reject(new Error(`Expected welcome, got ${welcome.type}`));
          return;
        }
        resolve({ ws, uuid: identity.uuid });
      });
    });

    ws.once("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Relay forwarding", () => {
  let server: RelayServer;
  let port: number;

  beforeEach(() => {
    server = new RelayServer(testRelayOpts({ baseUrl: "wss://relay.dicode.app" }));
    port = server.port;
  });

  afterEach(async () => {
    await server.close();
  });

  it("forward() sends request message to correct WebSocket client", async () => {
    const { ws, uuid } = await performHandshake(port);

    const receivedMessages: RequestMessage[] = [];
    ws.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
        string,
        unknown
      >;
      if (msg.type === "request") {
        receivedMessages.push(msg as unknown as RequestMessage);
        const req = msg as RequestMessage;
        const response: ResponseMessage = {
          type: "response",
          id: req.id,
          status: 200,
          headers: { "Content-Type": ["application/json"] },
          body: Buffer.from(JSON.stringify({ ok: true })).toString("base64"),
        };
        ws.send(JSON.stringify(response));
      }
    });

    const result = await server.forward(
      uuid,
      "POST",
      "/hooks/oauth-complete",
      { "Content-Type": ["application/json"] },
      Buffer.from(JSON.stringify({ test: "payload" })),
    );

    expect(result.status).toBe(200);
    expect(receivedMessages).toHaveLength(1);
    expect(receivedMessages[0]?.path).toBe("/hooks/oauth-complete");
    expect(receivedMessages[0]?.method).toBe("POST");

    ws.close();
  });

  it("client sends response, forward() resolves with response body", async () => {
    const { ws, uuid } = await performHandshake(port);

    ws.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
        string,
        unknown
      >;
      if (msg.type === "request") {
        const req = msg as RequestMessage;
        const response: ResponseMessage = {
          type: "response",
          id: req.id,
          status: 201,
          headers: {},
          body: Buffer.from("created").toString("base64"),
        };
        ws.send(JSON.stringify(response));
      }
    });

    const result = await server.forward(uuid, "POST", "/hooks/test", {}, Buffer.from("body"));

    expect(result.status).toBe(201);
    expect(Buffer.from(result.body, "base64").toString()).toBe("created");

    ws.close();
  });

  it("forward to unknown UUID throws ClientNotConnectedError", async () => {
    await expect(server.forward("a".repeat(64), "GET", "/", {}, Buffer.alloc(0))).rejects.toThrow(
      ClientNotConnectedError,
    );
  });

  it("forward to unknown UUID throws error with correct name", async () => {
    await expect(server.forward("b".repeat(64), "GET", "/", {}, Buffer.alloc(0))).rejects.toThrow(
      "Client not connected",
    );
  });

  it("ForwardTimeoutError has correct name", () => {
    const err = new ForwardTimeoutError("test-id");
    expect(err.name).toBe("ForwardTimeoutError");
    expect(err.message).toContain("test-id");
  });

  it("ClientNotConnectedError has correct name", () => {
    const err = new ClientNotConnectedError("some-uuid");
    expect(err.name).toBe("ClientNotConnectedError");
    expect(err.message).toContain("some-uuid");
  });

  it("server.close() rejects pending forward promises", async () => {
    // Create a separate server instance so closing it does not interfere with afterEach
    const tempServer = new RelayServer(testRelayOpts({ baseUrl: "wss://test.local" }));
    const { uuid } = await performHandshake(tempServer.port);

    // Don't handle messages — let it hang
    const forwardPromise = tempServer.forward(uuid, "POST", "/hooks/test", {}, Buffer.from("body"));

    // Close the server — should reject pending requests
    await tempServer.close();

    await expect(forwardPromise).rejects.toThrow();
  });

  it("concurrent forwards to same client both resolve", async () => {
    const { ws, uuid } = await performHandshake(port);

    ws.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
        string,
        unknown
      >;
      if (msg.type === "request") {
        const req = msg as RequestMessage;
        // Respond asynchronously to test concurrency
        setTimeout(() => {
          const response: ResponseMessage = {
            type: "response",
            id: req.id,
            status: 200,
            headers: {},
            body: Buffer.from(req.path).toString("base64"),
          };
          ws.send(JSON.stringify(response));
        }, 10);
      }
    });

    const [r1, r2] = await Promise.all([
      server.forward(uuid, "GET", "/path1", {}, Buffer.alloc(0)),
      server.forward(uuid, "GET", "/path2", {}, Buffer.alloc(0)),
    ]);

    expect(Buffer.from(r1.body, "base64").toString()).toBe("/path1");
    expect(Buffer.from(r2.body, "base64").toString()).toBe("/path2");

    ws.close();
    await waitForClose(ws);
  });
});
