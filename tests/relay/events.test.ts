import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { RelayServer } from "../../src/relay/server.js";
import { testRelayOpts } from "../helpers.js";

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

function performHandshake(
  ws: WebSocket,
  identity: ReturnType<typeof generateSigningIdentity>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.on("message", (data: Buffer | string) => {
      const msg = JSON.parse(typeof data === "string" ? data : data.toString("utf8")) as {
        type: string;
        nonce?: string;
      };
      if (msg.type === "challenge" && msg.nonce !== undefined) {
        const nonceBytes = Buffer.from(msg.nonce, "hex");
        const timestamp = Math.floor(Date.now() / 1000);
        const tsBytes = Buffer.allocUnsafe(8);
        tsBytes.writeBigUInt64BE(BigInt(timestamp));
        const sigMessage = Buffer.concat([nonceBytes, tsBytes]);
        ws.send(
          JSON.stringify({
            type: "hello",
            uuid: identity.uuid,
            pubkey: identity.pubkeyBase64,
            decrypt_pubkey: identity.decryptPubkeyBase64,
            sig: identity.sign(sigMessage),
            timestamp,
          }),
        );
      } else if (msg.type === "welcome") {
        resolve();
      } else if (msg.type === "error") {
        reject(new Error("handshake failed"));
      }
    });
  });
}

describe("RelayServer events", () => {
  let server: RelayServer;

  beforeEach(() => {
    server = new RelayServer(testRelayOpts({ port: 0 }));
  });

  afterEach(async () => {
    await server.close();
  });

  it("emits client:connected on successful handshake", async () => {
    const identity = generateSigningIdentity();
    const connected = new Promise<string>((resolve) => {
      server.on("client:connected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const ws = new WebSocket(`ws://localhost:${server.port.toString()}`);
    await performHandshake(ws, identity);

    const uuid = await connected;
    expect(uuid).toBe(identity.uuid);
    ws.close();
  });

  it("emits client:disconnected when client closes connection", async () => {
    const identity = generateSigningIdentity();
    const disconnected = new Promise<string>((resolve) => {
      server.on("client:disconnected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const ws = new WebSocket(`ws://localhost:${server.port.toString()}`);
    await performHandshake(ws, identity);
    ws.close();

    const uuid = await disconnected;
    expect(uuid).toBe(identity.uuid);
  });
});
