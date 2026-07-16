/**
 * Broker session pubkey selection.
 * The daemon advertises decrypt_pubkey in the v4 hello; the OAuth session's
 * ECIES recipient must be that decrypt pubkey, not the sign pubkey the
 * broker extracted from the TLS client certificate.
 */

import type { Server } from "node:http";
import { randomBytes } from "node:crypto";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildBrokerRouter } from "../../src/broker/router.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SessionStore } from "../../src/broker/sessions.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  testSessionTtlMs,
  type MtlsRelayFixture,
  type TestDaemon,
} from "../helpers.js";

function testProviders(): ReadonlyMap<string, ProviderConfig> {
  return new Map([
    [
      "github",
      { grantKey: "github", clientId: "test-client-id", pkce: true, scopes: ["user", "repo"] },
    ],
  ]);
}

async function startAuth(
  httpPort: number,
  daemon: TestDaemon,
  sessionId: string,
): Promise<Response> {
  const pkceChallenge = randomBytes(32).toString("base64url");
  const timestamp = Math.floor(Date.now() / 1000);
  const sig = await daemon.identity.signAuthPayload(sessionId, pkceChallenge, "github", timestamp);

  const url =
    `http://localhost:${httpPort.toString()}/auth/github` +
    `?session=${encodeURIComponent(sessionId)}` +
    `&challenge=${encodeURIComponent(pkceChallenge)}` +
    `&relay_uuid=${daemon.identity.uuid}` +
    `&sig=${encodeURIComponent(sig)}` +
    `&timestamp=${timestamp.toString()}`;
  return fetch(url, { redirect: "manual" });
}

describe("Broker ECIES recipient selection", () => {
  let fixture: MtlsRelayFixture;
  let httpServer: Server;
  let httpPort: number;
  let sessions: SessionStore;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    sessions = new SessionStore(testSessionTtlMs);

    const app = express();
    app.use(buildBrokerRouter(fixture.relay, sessions, testProviders()));

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
    await fixture.close();
    sessions.clear();
  });

  it("session.pubkey = decryptPubkey, distinct from sign pubkey", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const response = await startAuth(httpPort, daemon, sessionId);
    expect(response.status).toBe(302);

    const decryptPubkey = Buffer.from(daemon.identity.decryptPubkeyB64, "base64");
    const signPubkey = Buffer.from(daemon.identity.signPubkeyB64, "base64");

    const stored = sessions.get(sessionId);
    expect(stored).toBeDefined();
    expect(stored?.pubkey.equals(decryptPubkey)).toBe(true);
    expect(stored?.pubkey.equals(signPubkey)).toBe(false);

    ws.terminate();
  });
});
