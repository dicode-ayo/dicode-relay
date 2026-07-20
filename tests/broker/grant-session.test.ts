/**
 * Grant leg past the 302 (#107).
 *
 * The broker's /auth redirects into Grant's /connect/:provider, which requires
 * `req.session`. With no session middleware Grant's Express handler errors
 * "Grant: mount session middleware first" and the browser leg 500s — the bug
 * these tests pin. Mounting the stateless flow cookie (cookie-session) lets the
 * /connect leg run to its provider redirect.
 */

import type { Server } from "node:http";
import { randomBytes } from "node:crypto";
import express from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildGrantMiddleware } from "../../src/broker/grant.js";
import { buildBrokerRouter } from "../../src/broker/router.js";
import type { ProviderConfig } from "../../src/broker/providers.js";
import { SeenSet } from "../../src/broker/sessions.js";
import type { BrokerSigningKey } from "../../src/shared/signing.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  testSessionTtlMs,
  testBrokerKey,
  mountFlowSession,
  cookiesFrom,
  type MtlsRelayFixture,
} from "../helpers.js";

function githubProviders(): ReadonlyMap<string, ProviderConfig> {
  return new Map([
    ["github", { grantKey: "github", clientId: "gh-client-id", pkce: true, scopes: ["user"] }],
  ]);
}

async function listen(app: express.Express): Promise<{ server: Server; port: number }> {
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => {
      resolve(s);
    });
  });
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  return { server, port: addr.port };
}

describe("Grant leg (/connect/:provider)", () => {
  let server: Server;

  afterEach(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  });

  it("without session middleware → 500 'mount session middleware first' (the bug)", async () => {
    const app = express();
    app.use(buildGrantMiddleware(githubProviders(), "https://relay.dicode.app"));
    app.use(
      (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        res.status(500).send(err instanceof Error ? err.message : "error");
      },
    );
    ({ server } = await listen(app));
    const addr = server.address() as { port: number };

    const res = await fetch(`http://localhost:${addr.port.toString()}/connect/github?state=abc`, {
      redirect: "manual",
    });
    expect(res.status).toBe(500);
    expect(await res.text()).toContain("mount session middleware first");
  });

  it("with the flow cookie mounted → 302 to the provider authorize URL", async () => {
    const brokerKey = testBrokerKey();
    const app = express();
    mountFlowSession(app, brokerKey);
    app.use(buildGrantMiddleware(githubProviders(), "https://relay.dicode.app"));
    ({ server } = await listen(app));
    const addr = server.address() as { port: number };

    const sessionId = "550e8400-e29b-41d4-a716-446655440099";
    const res = await fetch(
      `http://localhost:${addr.port.toString()}/connect/github?state=${sessionId}`,
      { redirect: "manual" },
    );

    expect(res.status).toBe(302);
    const location = res.headers.get("location") ?? "";
    expect(location).toContain("https://github.com/login/oauth/authorize");
    // Grant round-trips the broker's session id as the OAuth state.
    expect(location).toContain(`state=${sessionId}`);
    // PKCE is on → a code challenge is included.
    expect(location).toContain("code_challenge=");
    expect(location).toContain("code_challenge_method=S256");
  });
});

describe("Full browser leg: /auth → /connect (cookie carried across)", () => {
  let fixture: MtlsRelayFixture;
  let server: Server;
  let port: number;
  let brokerKey: BrokerSigningKey;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
    brokerKey = testBrokerKey();
    const app = express();
    mountFlowSession(app, brokerKey);
    app.use(buildGrantMiddleware(githubProviders(), "https://relay.dicode.app"));
    app.use(
      buildBrokerRouter(
        fixture.relay,
        new SeenSet(testSessionTtlMs),
        githubProviders(),
        30,
        brokerKey,
      ),
    );
    ({ server, port } = await listen(app));
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    await fixture.close();
  });

  it("signed /auth sets the flow cookie, which /connect consumes → provider redirect", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const sessionId = "550e8400-e29b-41d4-a716-4466554400aa";
    const challenge = randomBytes(32).toString("base64url");
    const ts = Math.floor(Date.now() / 1000);
    const sig = await daemon.identity.signAuthPayload(sessionId, challenge, "github", ts);
    const authUrl =
      `http://localhost:${port.toString()}/auth/github` +
      `?session=${encodeURIComponent(sessionId)}` +
      `&challenge=${encodeURIComponent(challenge)}` +
      `&relay_uuid=${daemon.identity.uuid}` +
      `&sig=${encodeURIComponent(sig)}` +
      `&timestamp=${ts.toString()}`;

    const authRes = await fetch(authUrl, { redirect: "manual" });
    expect(authRes.status).toBe(302);
    expect(authRes.headers.get("location")).toContain("/connect/github");
    const cookie = cookiesFrom(authRes);
    expect(cookie).not.toBe("");

    // Follow into the Grant leg carrying the cookie the browser would.
    const connectRes = await fetch(
      `http://localhost:${port.toString()}/connect/github?state=${sessionId}`,
      { redirect: "manual", headers: { cookie } },
    );
    expect(connectRes.status).toBe(302);
    expect(connectRes.headers.get("location")).toContain(
      "https://github.com/login/oauth/authorize",
    );

    ws.terminate();
  });
});
