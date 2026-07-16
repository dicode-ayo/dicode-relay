/**
 * Relay handshake tests — v4 welcome shape and frame-handling behavior
 * around registration. Certificate admission (close codes, uuid derivation,
 * duplicate reconnect) lives in mtls.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { PROTOCOL_VERSION } from "../../src/relay/server.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseError,
  parseRequest,
  responseEnvelope,
  type MtlsRelayFixture,
} from "../helpers.js";

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

describe("Relay handshake (v4)", () => {
  let fixture: MtlsRelayFixture;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
  });

  afterEach(async () => {
    await fixture.close();
  });

  it("welcome carries the daemon hook URL and protocol 4", async () => {
    const daemon = await testDaemon(fixture);
    const { ws, welcome } = await connectDaemon(fixture, daemon);

    expect(welcome.url).toBe(`wss://relay.dicode.app/u/${daemon.identity.uuid}/hooks/`);
    expect(welcome.protocol).toBe(PROTOCOL_VERSION);
    expect(welcome.protocol).toBe(4);
    // No broker signing key configured on this fixture → field absent.
    expect(welcome.brokerPubkey).toBeUndefined();
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    ws.terminate();
  });

  it("welcome announces the broker delivery-signing pubkey when configured", async () => {
    const announcing = await startMtlsRelay({
      baseUrl: "wss://relay.dicode.app",
      brokerPubkey: "TEST-BROKER-PUBKEY",
    });
    try {
      const daemon = await testDaemon(announcing);
      const { ws, welcome } = await connectDaemon(announcing, daemon);
      expect(welcome.brokerPubkey).toBe("TEST-BROKER-PUBKEY");
      ws.terminate();
    } finally {
      await announcing.close();
    }
  });

  it("invalid JSON before registration → error + close", async () => {
    const daemon = await testDaemon(fixture);
    const ws = new WebSocket(fixture.url, { agent: daemon.agent });

    const errorMessage = await new Promise<string>((resolve, reject) => {
      ws.on("open", () => {
        ws.send("not json");
      });
      ws.on("message", (data: Buffer | string) => {
        const e = parseError(data);
        if (e !== null) resolve(e.message);
      });
      ws.on("error", reject);
    });
    expect(errorMessage).toContain("invalid JSON");
    await waitForClose(ws);
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });

  it("post-registration non-response frames are silently dropped — connection stays live", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req === null) return;
      ws.send(responseEnvelope({ id: req.id, status: 200, body: "" }));
    });

    // Neither a garbage envelope nor a second hello may tear the
    // registration down after the daemon is registered.
    ws.send(JSON.stringify({ nonsense: { foo: "bar" } }));
    ws.send(JSON.stringify({ hello: { decrypt_pubkey: daemon.identity.decryptPubkeyB64 } }));

    // The connection must still serve a full forward round-trip.
    const result = await fixture.relay.forward(
      daemon.identity.uuid,
      "GET",
      "/hooks/ping",
      {},
      Buffer.alloc(0),
    );
    expect(result.status).toBe(200);
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    ws.terminate();
  });

  it("connection cleanup: client disconnects → registry entry removed", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    const disconnected = new Promise<void>((resolve) => {
      fixture.relay.once("client:disconnected", () => {
        resolve();
      });
    });
    ws.close();
    await disconnected;

    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });
});
