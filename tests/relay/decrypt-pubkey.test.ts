/**
 * Granular hello.decrypt_pubkey validation. The broad admission surface
 * (cert identity, close codes, one malformed + one off-curve case) lives in
 * mtls.test.ts; this file walks the finer-grained rejection branches.
 */

import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { CLOSE_BAD_HELLO } from "../../src/relay/server.js";
import {
  startMtlsRelay,
  testDaemon,
  helloEnvelope,
  parseError,
  type MtlsRelayFixture,
  type TestDaemon,
} from "../helpers.js";

let fixture: MtlsRelayFixture;
let daemon: TestDaemon;

beforeAll(async () => {
  fixture = await startMtlsRelay();
  daemon = await testDaemon(fixture);
});

afterAll(async () => {
  await fixture.close();
});

/** Dial with the daemon's cert, send a hello with the given decrypt_pubkey,
 *  and resolve with the error message + close code. */
function sendHelloExpectClose(
  decryptPubkey: string,
): Promise<{ code: number; errorMessage: string | null }> {
  const ws = new WebSocket(fixture.url, { agent: daemon.agent });
  return new Promise((resolve, reject) => {
    let errorMessage: string | null = null;
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error("close timeout"));
    }, 5000);
    ws.on("open", () => {
      ws.send(helloEnvelope({ decrypt_pubkey: decryptPubkey }));
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

describe("Relay handshake — decrypt_pubkey validation", () => {
  it("empty decrypt_pubkey: rejected as a required field", async () => {
    const { code, errorMessage } = await sendHelloExpectClose("");
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("decrypt_pubkey is required");
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });

  it("non-base64 decrypt_pubkey: rejected with clear error", async () => {
    // Buffer.from(x, "base64") skips invalid chars, so this decodes to too
    // few bytes and must trip the shape check.
    const { code, errorMessage } = await sendHelloExpectClose("!!!not-base64!!!");
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("decrypt_pubkey");
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });

  it("decrypt_pubkey wrong length (32 bytes): rejected with clear error", async () => {
    const short = randomBytes(32).toString("base64");
    const { code, errorMessage } = await sendHelloExpectClose(short);
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("decrypt_pubkey must be 65 bytes starting with 0x04");
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });

  it("decrypt_pubkey with all-zero coordinates: structurally valid but not on curve", async () => {
    // 0x04 prefix + 64 zero bytes — passes the length/prefix check, fails
    // the createPublicKey on-curve import.
    const offCurve = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0x00)]);
    const { code, errorMessage } = await sendHelloExpectClose(offCurve.toString("base64"));
    expect(code).toBe(CLOSE_BAD_HELLO);
    expect(errorMessage).toContain("decrypt_pubkey is not a valid P-256 point");
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });
});
