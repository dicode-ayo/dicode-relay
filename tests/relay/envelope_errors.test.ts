/**
 * Envelope-level error paths introduced by the protobuf refactor
 * (dicode-relay#57). Covers the two branches that fire before the
 * hello message can be verified, plus the status-code range guard
 * on the response side.
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { RelayServer } from "../../src/relay/server.js";
import {
  helloEnvelope,
  parseChallenge,
  parseError,
  parseWelcome,
  testRelayOpts,
} from "../helpers.js";

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

describe("Envelope error paths", () => {
  let server: RelayServer;
  let port: number;

  beforeEach(() => {
    server = new RelayServer(testRelayOpts({ baseUrl: "wss://x" }));
    port = server.port;
  });

  afterEach(async () => {
    await server.close();
  });

  it("first message is a response envelope → error + close (wrong envelope variant before registration)", async () => {
    const ws = new WebSocket(`ws://localhost:${port.toString()}`);
    const reply = await new Promise<string>((resolve, reject) => {
      ws.once("message", () => {
        // Drop the challenge and send a response envelope, which is invalid
        // before registration. The server should reject with "expected hello".
        ws.send(
          JSON.stringify({
            response: {
              id: "00000000-0000-0000-0000-000000000000",
              status: 200,
              body: "",
            },
          }),
        );
        ws.once("message", (data: Buffer | string) => {
          const e = parseError(data);
          if (e) resolve(e.message);
          else reject(new Error(`unexpected envelope: ${data.toString()}`));
        });
      });
      ws.once("error", reject);
    });
    expect(reply).toContain("hello");
    await waitForClose(ws);
  });

  it("malformed envelope (not parseable as ClientMessage) → error + close before registration", async () => {
    const ws = new WebSocket(`ws://localhost:${port.toString()}`);
    const reply = await new Promise<string>((resolve, reject) => {
      ws.once("message", () => {
        // Garbage shape — has no valid envelope key. fromJson throws.
        ws.send(JSON.stringify({ nonsense: { foo: "bar" } }));
        ws.once("message", (data: Buffer | string) => {
          const e = parseError(data);
          if (e) resolve(e.message);
          else reject(new Error(`unexpected envelope: ${data.toString()}`));
        });
      });
      ws.once("error", reject);
    });
    expect(reply).toContain("hello");
    await waitForClose(ws);
  });

  it("response with out-of-range status is silently dropped (pending request times out)", async () => {
    // Run a full handshake, then have the daemon reply with status=50. The
    // forward() promise should reject with a timeout (the server drops the
    // bogus status rather than resolving with it).
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const { publicKey: dk } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const spki = publicKey as Buffer;
    const pub = spki.subarray(spki.length - 65);
    const dkSpki = dk as Buffer;
    const decryptPub = dkSpki.subarray(dkSpki.length - 65);
    const uuid = createHash("sha256").update(pub).digest("hex");

    const ws = new WebSocket(`ws://localhost:${port.toString()}`);
    await new Promise<void>((resolve, reject) => {
      ws.once("message", (data: Buffer | string) => {
        const ch = parseChallenge(data);
        if (!ch) {
          reject(new Error("no challenge"));
          return;
        }
        const ts = Math.floor(Date.now() / 1000);
        const nonceBytes = Buffer.from(ch.nonce, "hex");
        const tsBytes = Buffer.allocUnsafe(8);
        tsBytes.writeBigUInt64BE(BigInt(ts));
        const signer = createSign("SHA256");
        signer.update(Buffer.concat([nonceBytes, tsBytes]));
        ws.send(
          helloEnvelope({
            uuid,
            pubkey: pub.toString("base64"),
            decrypt_pubkey: decryptPub.toString("base64"),
            sig: signer.sign(privateKey, "base64"),
            timestamp: ts,
          }),
        );
        ws.once("message", (data2: Buffer | string) => {
          if (parseWelcome(data2)) resolve();
          else reject(new Error("handshake failed"));
        });
      });
    });

    ws.on("message", (data: Buffer | string) => {
      const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
        string,
        unknown
      >;
      const req = env.request as { id: string } | undefined;
      if (req !== undefined) {
        // Reply with an out-of-range status. Server must drop it, forward()
        // must time out rather than resolve with status=50.
        ws.send(
          JSON.stringify({
            response: { id: req.id, status: 50, body: "" },
          }),
        );
      }
    });

    // Use a short timeout so the test completes quickly on the expected drop.
    const shortServer = new RelayServer(
      testRelayOpts({ baseUrl: "wss://x", requestTimeoutMs: 200 }),
    );
    try {
      // Reuse the same handshake path against the short-timeout server
      // would be overkill; easier to just assert the behavior against the
      // running one with a manual race.
      const raced = await Promise.race([
        server.forward(uuid, "GET", "/hooks/anything", {}, Buffer.alloc(0)).then(() => "resolved"),
        new Promise<string>((resolve) => {
          setTimeout(() => {
            resolve("dropped");
          }, 400);
        }),
      ]);
      expect(raced).toBe("dropped");
    } finally {
      await shortServer.close();
      ws.close();
      await waitForClose(ws);
    }
  });
});
