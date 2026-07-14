/**
 * GET /providers endpoint tests — verifies metadata exposure and zero secret leakage.
 */

import { describe, expect, it, beforeAll, afterAll } from "vitest";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { buildProviderMap } from "../../src/broker/providers.js";
import type { PublicProviderInfo } from "../../src/broker/providers.js";
import { defaultConfig } from "../../src/config.js";

describe("GET /providers", () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    const config = defaultConfig();
    // Override broker.providers with test fixtures.
    config.broker.providers = {
      github: {
        client_id: "test-github-id",
        client_secret: "test-github-secret",
        pkce: true,
        scopes: ["user", "repo"],
      },
      slack: {
        client_id: "test-slack-id",
        pkce: true,
        scopes: ["channels:read"],
      },
      // Empty client_id → skipped by buildProviderMap.
      stripe: {
        client_id: "",
        pkce: false,
        scopes: ["read_write"],
      },
    };

    const providerMap = buildProviderMap(config);

    const app = express();
    app.get("/providers", (_req, res) => {
      const list = Array.from(providerMap.entries()).map(([key, cfg]): PublicProviderInfo => ({
        key,
        pkce: cfg.pkce,
        scopes: cfg.scopes,
        secret_required: cfg.clientSecret !== undefined,
        configured: cfg.clientId !== "",
      }));
      res.json(list);
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        port = (server.address() as AddressInfo).port;
        resolve();
      });
    });
  });

  afterAll(
    () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      }),
  );

  it("lists configured providers without exposing secrets", async () => {
    const res = await fetch(`http://127.0.0.1:${String(port)}/providers`);
    expect(res.ok).toBe(true);
    const body = (await res.json()) as Record<string, unknown>[];

    // Stripe was empty → skipped by buildProviderMap.
    expect(body.length).toBe(2);
    const keys = body.map((p) => p.key).sort();
    expect(keys).toEqual(["github", "slack"]);

    const github = body.find((p) => p.key === "github");
    expect(github).toBeDefined();
    expect(github?.pkce).toBe(true);
    expect(github?.scopes).toEqual(["user", "repo"]);
    expect(github?.secret_required).toBe(true);
    expect(github?.configured).toBe(true);

    const slack = body.find((p) => p.key === "slack");
    expect(slack).toBeDefined();
    expect(slack?.secret_required).toBe(false); // PKCE-only, no secret
    expect(slack?.pkce).toBe(true);
    expect(slack?.configured).toBe(true);

    // Verify NO secret material leaks.
    for (const p of body) {
      expect(p).not.toHaveProperty("client_id");
      expect(p).not.toHaveProperty("client_secret");
      expect(p).not.toHaveProperty("clientId");
      expect(p).not.toHaveProperty("clientSecret");
      const text = JSON.stringify(p);
      expect(text).not.toContain("test-github-secret");
      expect(text).not.toContain("test-github-id");
      expect(text).not.toContain("test-slack-id");
    }
  });

  it("returns an empty array if no providers are configured", async () => {
    const config = defaultConfig();
    config.broker.providers = {};
    const map = buildProviderMap(config);
    expect(map.size).toBe(0);

    // Mount a second server with an empty map and verify the response.
    const app = express();
    app.get("/providers", (_req, res) => {
      const list = Array.from(map.entries()).map(([key, cfg]): PublicProviderInfo => ({
        key,
        pkce: cfg.pkce,
        scopes: cfg.scopes,
        secret_required: cfg.clientSecret !== undefined,
        configured: cfg.clientId !== "",
      }));
      res.json(list);
    });

    const emptyServer = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => {
        resolve(s);
      });
    });
    const emptyPort = (emptyServer.address() as AddressInfo).port;

    try {
      const res = await fetch(`http://127.0.0.1:${String(emptyPort)}/providers`);
      expect(res.ok).toBe(true);
      const body = (await res.json()) as unknown[];
      expect(body).toEqual([]);
    } finally {
      await new Promise<void>((resolve) => {
        emptyServer.close(() => {
          resolve();
        });
      });
    }
  });
});
