/**
 * E2E mock provider tests — real crypto, in-process RelayServer, no mocks.
 *
 * Covers:
 *  - GET /connect/mock — short-circuit redirect to /callback/mock
 *  - POST /_test/deliver — low-level wire-shape primitive
 */

import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { Server } from "node:http";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildE2EMockRouter,
  isE2EMockEnabled,
  MOCK_PROVIDER_KEY,
} from "../../src/broker/e2e-mock.js";
import type { Session } from "../../src/broker/sessions.js";
import { verifyDeliverySignature } from "../../src/shared/signing.js";
import type { BrokerSigningKey } from "../../src/shared/signing.js";
import { loadBrokerSigningKey } from "../../src/shared/signing.js";
import { Identity } from "../../src/client/identity.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseRequest,
  responseEnvelope,
  mountFlowSession,
  flowCookieHeader,
  type MtlsRelayFixture,
} from "../helpers.js";

/** 65-byte uncompressed decrypt pubkey for session fixtures. */
function decryptPubkeyBytes(identity: Identity): Buffer {
  return Buffer.from(identity.decryptPubkeyB64, "base64");
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

describe("E2E mock router", () => {
  let fixture: MtlsRelayFixture;
  let httpServer: Server;
  let httpPort: number;
  let brokerKey: BrokerSigningKey;

  /** A mock-provider flow session used to seal a request Cookie header. */
  function mockSession(sessionId: string, overrides?: Partial<Session>): Session {
    return {
      sessionId,
      relayUuid: "a".repeat(64),
      pubkey: randomBytes(65),
      pkceChallenge: "challenge",
      provider: MOCK_PROVIDER_KEY,
      expiresAt: Date.now() + 60_000,
      ...overrides,
    };
  }

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.test.local" });
    // Use an inline PEM so tests do not touch disk.
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    brokerKey = loadBrokerSigningKey({ BROKER_SIGNING_KEY: pair.privateKey }, "/tmp");

    const app = express();
    mountFlowSession(app, brokerKey);
    app.use(buildE2EMockRouter(fixture.relay, brokerKey));

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
  });

  // -------------------------------------------------------------------------
  // /connect/mock
  // -------------------------------------------------------------------------

  describe("GET /connect/mock", () => {
    it("valid session → 302 redirect to /callback/mock with synthetic token", async () => {
      const sessionId = "550e8400-e29b-41d4-a716-446655440000";
      const identity = await Identity.generate();
      const cookie = await flowCookieHeader(
        brokerKey,
        mockSession(sessionId, { relayUuid: identity.uuid, pubkey: decryptPubkeyBytes(identity) }),
      );

      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=${sessionId}`,
        { redirect: "manual", headers: { cookie } },
      );

      expect(response.status).toBe(302);
      const location = response.headers.get("location");
      expect(location).not.toBeNull();
      // Relative redirect — matches router.ts style. Parse against a dummy
      // base so URL semantics still work.
      const url = new URL(location ?? "", "http://dummy.local");
      expect(url.pathname).toBe("/callback/mock");
      expect(url.searchParams.get("state")).toBe(sessionId);
      expect(url.searchParams.get("access_token")).toBe(`mock-token-${sessionId}`);
      expect(url.searchParams.get("token_type")).toBe("bearer");
    });

    it("expired session → 400", async () => {
      const sessionId = "bb0e8400-e29b-41d4-a716-446655440000";
      const cookie = await flowCookieHeader(
        brokerKey,
        mockSession(sessionId, { expiresAt: Date.now() - 1 }),
      );

      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=${sessionId}`,
        { headers: { cookie } },
      );
      expect(response.status).toBe(400);
    });

    it("missing state → 400", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/connect/mock`);
      expect(response.status).toBe(400);
    });

    it("no flow cookie → 400", async () => {
      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=does-not-exist`,
      );
      expect(response.status).toBe(400);
    });

    it("session for a non-mock provider → 400", async () => {
      const sessionId = "aa0e8400-e29b-41d4-a716-446655440000";
      const cookie = await flowCookieHeader(
        brokerKey,
        mockSession(sessionId, { provider: "github" }),
      );

      const response = await fetch(
        `http://localhost:${httpPort.toString()}/connect/mock?state=${sessionId}`,
        { headers: { cookie } },
      );
      expect(response.status).toBe(400);
    });
  });

  // -------------------------------------------------------------------------
  // /_test/deliver
  // -------------------------------------------------------------------------

  describe("POST /_test/deliver", () => {
    it("missing fields → 400", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uuid: "x" }),
      });
      expect(response.status).toBe(400);
    });

    it("unknown daemon uuid → 404", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: "a".repeat(64),
          session_id: randomBytes(16).toString("hex"),
          provider: "github",
          tokens: { access_token: "t" },
        }),
      });
      expect(response.status).toBe(404);
    });

    it("connected daemon → encrypts + signs + forwards; daemon can verify sig", async () => {
      const daemon = await testDaemon(fixture);
      const { ws } = await connectDaemon(fixture, daemon);

      // Capture the request message that arrives at the daemon end.
      const forwarded: { id: string; path: string; body: string }[] = [];
      ws.on("message", (data: Buffer | string) => {
        const req = parseRequest(data);
        if (req !== null) {
          forwarded.push(req);
          ws.send(
            responseEnvelope({
              id: req.id,
              status: 200,
              body: Buffer.from("ok").toString("base64"),
            }),
          );
        }
      });

      const sessionId = randomBytes(16).toString("hex");
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: daemon.identity.uuid,
          session_id: sessionId,
          provider: "github",
          tokens: { access_token: "test-token" },
        }),
      });

      expect(response.status).toBe(200);
      expect(forwarded).toHaveLength(1);
      expect(forwarded[0]?.path).toBe("/hooks/oauth-complete");

      // The caller sees ONLY the daemon's status — the decoded daemon body
      // must not be reflected back (unauthenticated echo reducer).
      const respJson = (await response.json()) as Record<string, unknown>;
      expect(respJson).toEqual({ daemon_status: 200 });
      expect(respJson).not.toHaveProperty("daemon_body");

      const bodyJson = JSON.parse(
        Buffer.from(forwarded[0]?.body ?? "", "base64").toString("utf8"),
      ) as {
        type: string;
        session_id: string;
        ephemeral_pubkey: string;
        ciphertext: string;
        nonce: string;
        broker_sig: string;
      };
      expect(bodyJson.type).toBe("oauth_token_delivery");
      expect(bodyJson.session_id).toBe(sessionId);
      expect(
        verifyDeliverySignature(
          brokerKey.publicKeyBase64,
          bodyJson.broker_sig,
          bodyJson.type,
          bodyJson.session_id,
          bodyJson.ephemeral_pubkey,
          bodyJson.ciphertext,
          bodyJson.nonce,
        ),
      ).toBe(true);

      ws.terminate();
    });

    it("rejects tokens=null as 400 (typeof null === 'object' quirk)", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: "a".repeat(64),
          session_id: "x",
          provider: "github",
          tokens: null,
        }),
      });
      expect(response.status).toBe(400);
    });

    it("rejects tokens=[] as 400 (array is not a plain object)", async () => {
      const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uuid: "a".repeat(64),
          session_id: "x",
          provider: "github",
          tokens: [],
        }),
      });
      expect(response.status).toBe(400);
    });
  });
});

// ---------------------------------------------------------------------------
// isE2EMockEnabled()
// ---------------------------------------------------------------------------

describe("isE2EMockEnabled", () => {
  const savedFlag = process.env.DICODE_E2E_MOCK_PROVIDER;
  const savedNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (savedFlag === undefined) {
      delete process.env.DICODE_E2E_MOCK_PROVIDER;
    } else {
      process.env.DICODE_E2E_MOCK_PROVIDER = savedFlag;
    }
    if (savedNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = savedNodeEnv;
    }
  });

  it("returns false when env var unset", () => {
    delete process.env.DICODE_E2E_MOCK_PROVIDER;
    delete process.env.NODE_ENV;
    expect(isE2EMockEnabled()).toBe(false);
  });

  it("returns true when env var is exactly '1'", () => {
    process.env.DICODE_E2E_MOCK_PROVIDER = "1";
    delete process.env.NODE_ENV;
    expect(isE2EMockEnabled()).toBe(true);
  });

  it.each(["true", "TRUE", "yes", "on", "0", " 1", "1 ", ""])(
    "returns false for non-'1' value %p",
    (val) => {
      process.env.DICODE_E2E_MOCK_PROVIDER = val;
      delete process.env.NODE_ENV;
      expect(isE2EMockEnabled()).toBe(false);
    },
  );

  it("returns false when NODE_ENV=production even if flag='1' (fail-closed in prod)", () => {
    process.env.DICODE_E2E_MOCK_PROVIDER = "1";
    process.env.NODE_ENV = "production";
    expect(isE2EMockEnabled()).toBe(false);
  });

  it.each(["PRODUCTION", "Production", " production", "production ", "  PRODUCTION  "])(
    "still fails closed for oddly-cased/whitespaced NODE_ENV %p",
    (val) => {
      process.env.DICODE_E2E_MOCK_PROVIDER = "1";
      process.env.NODE_ENV = val;
      expect(isE2EMockEnabled()).toBe(false);
    },
  );
});

// ---------------------------------------------------------------------------
// Routes absent when the e2e-mock router is NOT mounted
// ---------------------------------------------------------------------------

describe("mock routes absent when flag unset", () => {
  let httpServer: Server;
  let httpPort: number;

  beforeEach(async () => {
    // Simulate index.ts's behavior when DICODE_E2E_MOCK_PROVIDER is off:
    // the e2e-mock router is simply never mounted.
    const app = express();
    app.use(express.json());
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
  });

  it("GET /connect/mock → 404", async () => {
    const response = await fetch(`http://localhost:${httpPort.toString()}/connect/mock?state=x`);
    expect(response.status).toBe(404);
  });

  it("POST /_test/deliver → 404", async () => {
    const response = await fetch(`http://localhost:${httpPort.toString()}/_test/deliver`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(response.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// The e2e-mock router must scope json() to its own routes, not globally.
// ---------------------------------------------------------------------------
//
// Verifies that mounting the e2e-mock router at the app root does not
// consume JSON bodies on unrelated routes (e.g. /u/:uuid/hooks/*).

describe("e2e-mock router body-passthrough on unrelated routes", () => {
  let httpServer: Server;
  let httpPort: number;
  let fixture: MtlsRelayFixture;
  let brokerKey: BrokerSigningKey;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.test.local" });
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    brokerKey = loadBrokerSigningKey({ BROKER_SIGNING_KEY: pair.privateKey }, "/tmp");

    const app = express();
    mountFlowSession(app, brokerKey);
    // Mount the e2e-mock router FIRST (same order as src/index.ts when the
    // flag is on) — this is the configuration we're guarding against.
    app.use(buildE2EMockRouter(fixture.relay, brokerKey));
    // A simple downstream handler that reads the raw body — stands in for
    // the /u/:uuid/hooks/* forward handler in src/index.ts.
    app.post(
      "/raw-echo",
      express.raw({ type: "*/*", limit: "5mb" }),
      (req: express.Request, res: express.Response) => {
        const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
        res.status(200).json({ length: body.length, body: body.toString("utf8") });
      },
    );

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
  });

  it("application/json POST body on an unrelated route reaches the downstream raw handler", async () => {
    const payload = JSON.stringify({ hello: "world" });
    const response = await fetch(`http://localhost:${httpPort.toString()}/raw-echo`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
    });
    expect(response.status).toBe(200);
    const seen = (await response.json()) as { length: number; body: string };
    expect(seen.length).toBe(payload.length);
    expect(seen.body).toBe(payload);
  });
});
