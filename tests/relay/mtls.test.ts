/**
 * mTLS admission tests — the v4 handshake surface.
 *
 * Every case runs against a real mTLS listener (helpers.startMtlsRelay):
 * identity extraction from the peer certificate, the 44xx close codes,
 * duplicate-uuid replacement, and registry/event wiring.
 */

import { webcrypto, X509Certificate } from "node:crypto";
import { Agent as HttpsAgent } from "node:https";
import type { Socket } from "node:net";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import WebSocket from "ws";
import * as x509 from "@peculiar/x509";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  helloEnvelope,
  parseError,
  type MtlsRelayFixture,
  type TestDaemon,
} from "../helpers.js";
import {
  CLOSE_BAD_HELLO,
  CLOSE_CERT_NOT_P256,
  CLOSE_NO_CLIENT_CERT,
} from "../../src/relay/server.js";
import { extractP256PointFromCert, uuidFromP256Point } from "../../src/shared/certs.js";

let fixture: MtlsRelayFixture;
let daemon: TestDaemon;

beforeAll(async () => {
  fixture = await startMtlsRelay();
  daemon = await testDaemon(fixture);
});

afterAll(async () => {
  await fixture.close();
});

/** Dial and capture the first error frame + close code. */
function dialExpectClose(
  agent: HttpsAgent | undefined,
  onOpen?: (ws: WebSocket) => void,
): Promise<{ code: number; errorMessage: string | null }> {
  const ws = new WebSocket(fixture.url, agent !== undefined ? { agent } : { ca: fixture.ca });
  return new Promise((resolve, reject) => {
    let errorMessage: string | null = null;
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error("close timeout"));
    }, 5000);
    ws.on("open", () => {
      onOpen?.(ws);
    });
    ws.on("message", (data: Buffer | string) => {
      const e = parseError(data);
      if (e !== null) errorMessage = e.message;
    });
    ws.on("close", (code: number) => {
      clearTimeout(timer);
      resolve({ code, errorMessage });
    });
    ws.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

describe("mTLS admission", () => {
  it("registers a daemon from its client cert and welcomes with the derived uuid", async () => {
    const { ws, welcome } = await connectDaemon(fixture, daemon);
    try {
      expect(welcome.url).toBe(`ws://localhost/u/${daemon.identity.uuid}/hooks/`);
      expect(welcome.protocol).toBe(4);
      expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

      const client = fixture.relay.getClient(daemon.identity.uuid);
      // Registry pubkey must be the cert's P-256 point == the identity sign key.
      expect(client.pubkey.toString("base64")).toBe(daemon.identity.signPubkeyB64);
      expect(client.decryptPubkey.toString("base64")).toBe(daemon.identity.decryptPubkeyB64);
    } finally {
      ws.terminate();
    }
  });

  it("uuid derivation matches sha256 over the cert point", () => {
    const cert = new X509Certificate(daemon.cert.certPem);
    const point = extractP256PointFromCert(cert);
    if (point === null) throw new Error("cert key is not P-256");
    expect(uuidFromP256Point(point)).toBe(daemon.identity.uuid);
  });

  it("closes 4401 when no client certificate is presented", async () => {
    const { code, errorMessage } = await dialExpectClose(undefined);
    expect(code).toBe(CLOSE_NO_CLIENT_CERT);
    expect(errorMessage).toContain("client certificate required");
  });

  it("closes 4402 for an RSA client certificate", async () => {
    const rsa = await selfSignedCert(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      },
      "CN=rsa-client",
    );
    const rsaAgent = new HttpsAgent({ cert: rsa.cert, key: rsa.key, ca: fixture.ca });
    const { code, errorMessage } = await dialExpectClose(rsaAgent);
    expect(code).toBe(CLOSE_CERT_NOT_P256);
    expect(errorMessage).toContain("P-256");
  });

  it("closes 4402 for a P-384 client certificate", async () => {
    const p384 = await selfSignedCert(
      { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" },
      "CN=p384-client",
    );
    const agent = new HttpsAgent({ cert: p384.cert, key: p384.key, ca: fixture.ca });
    const { code } = await dialExpectClose(agent);
    expect(code).toBe(CLOSE_CERT_NOT_P256);
  });

  it("closes 4400 when the first frame is not a hello", async () => {
    const { code } = await dialExpectClose(daemon.agent, (ws) => {
      ws.send(JSON.stringify({ response: { id: "x", status: 200, headers: {}, body: "" } }));
    });
    expect(code).toBe(CLOSE_BAD_HELLO);
  });

  it("closes 4400 for a hello with a malformed decrypt_pubkey", async () => {
    const { code, errorMessage } = await dialExpectClose(daemon.agent, (ws) => {
      ws.send(helloEnvelope({ decrypt_pubkey: Buffer.alloc(65, 7).toString("base64") }));
    });
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("decrypt_pubkey");
  });

  it("closes 4400 for a hello with an off-curve decrypt_pubkey", async () => {
    // Correct shape (65 bytes, 0x04 prefix) but not a point on P-256.
    const offCurve = Buffer.alloc(65, 0xab);
    offCurve[0] = 0x04;
    const { code, errorMessage } = await dialExpectClose(daemon.agent, (ws) => {
      ws.send(helloEnvelope({ decrypt_pubkey: offCurve.toString("base64") }));
    });
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("P-256");
  });

  it("replaces the previous socket on duplicate-uuid reconnect", async () => {
    const events: string[] = [];
    const onConn = (uuid: string): void => {
      events.push(`connect:${uuid}`);
    };
    const onDisc = (uuid: string): void => {
      events.push(`disconnect:${uuid}`);
    };
    fixture.relay.on("client:connected", onConn);
    fixture.relay.on("client:disconnected", onDisc);

    try {
      const first = await connectDaemon(fixture, daemon);
      const firstClosed = new Promise<void>((resolve) => {
        first.ws.on("close", () => {
          resolve();
        });
      });

      const second = await connectDaemon(fixture, daemon);
      await firstClosed;

      // The fresh registration must survive the old socket's close event.
      expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);
      const uuid = daemon.identity.uuid;
      expect(events).toEqual([`connect:${uuid}`, `disconnect:${uuid}`, `connect:${uuid}`]);

      second.ws.terminate();
      // Wait until the terminate propagates so afterAll close is clean.
      await new Promise<void>((resolve) => {
        second.ws.on("close", () => {
          resolve();
        });
      });
      expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
    } finally {
      fixture.relay.removeListener("client:connected", onConn);
      fixture.relay.removeListener("client:disconnected", onDisc);
    }
  });

  it("still surfaces the peer certificate across two sequential dials on one agent (session reuse)", async () => {
    // Node https.Agent may resume TLS sessions; the peer cert must still be
    // observable on the resumed socket or admission would break on reconnect.
    const one = await connectDaemon(fixture, daemon);
    one.ws.terminate();
    await new Promise<void>((resolve) => {
      one.ws.on("close", () => {
        resolve();
      });
    });
    const two = await connectDaemon(fixture, daemon);
    expect(two.welcome.url).toContain(daemon.identity.uuid);
    two.ws.terminate();
  });

  it("survives a peer that aborts the socket after a 4401 rejection (no process crash)", async () => {
    // A rejected connection returns from handleConnection before the
    // lifecycle listeners attach; a subsequent socket error must hit the
    // early safety 'error' listener, not crash the broker via an unhandled
    // EventEmitter 'error'.
    const uncaught: unknown[] = [];
    const onUncaught = (e: unknown): void => {
      uncaught.push(e);
    };
    process.on("uncaughtException", onUncaught);
    try {
      const ws = new WebSocket(fixture.url, { ca: fixture.ca });
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error("no rejection observed"));
        }, 5000);
        // Abort the TCP socket the moment the rejection arrives — the
        // broker's close-frame write then fails on a dead socket.
        ws.on("message", () => {
          const raw = (ws as unknown as { _socket?: Socket })._socket;
          raw?.destroy();
        });
        ws.on("close", () => {
          clearTimeout(timer);
          resolve();
        });
        ws.on("error", () => {
          clearTimeout(timer);
          resolve();
        });
      });
      // Give a potential broker-side 'error' event time to surface.
      await new Promise((r) => setTimeout(r, 200));
      expect(uncaught).toEqual([]);
      // The broker must still be serving: a normal daemon connects fine.
      const after = await connectDaemon(fixture, daemon);
      expect(after.welcome.url).toContain(daemon.identity.uuid);
      after.ws.terminate();
    } finally {
      process.off("uncaughtException", onUncaught);
    }
  });
});

/** Self-signed cert over an arbitrary (non-P-256) WebCrypto key algorithm. */
async function selfSignedCert(
  alg: webcrypto.RsaHashedKeyGenParams | webcrypto.EcKeyGenParams,
  name: string,
): Promise<{ cert: string; key: string }> {
  x509.cryptoProvider.set(webcrypto);
  const keys = await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "02",
    name,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: alg,
    keys,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
  });
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  const lines = pkcs8.toString("base64").match(/.{1,64}/g) ?? [];
  return {
    cert: cert.toString("pem"),
    key: `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`,
  };
}
