/**
 * Config loading tests — env resolution, Zod defaults, provider building.
 */

import { writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig, defaultConfig } from "../src/config.js";
import { buildProviderMap } from "../src/broker/providers.js";

// ---------------------------------------------------------------------------
// defaultConfig (Zod defaults)
// ---------------------------------------------------------------------------

describe("defaultConfig", () => {
  it("returns all defaults from Zod schema", () => {
    const cfg = defaultConfig();
    expect(cfg.server.port).toBe(5553);
    expect(cfg.relay.timestamp_tolerance_s).toBe(30);
    expect(cfg.relay.ping_interval_ms).toBe(30_000);
    expect(cfg.relay.pong_timeout_ms).toBe(10_000);
    expect(cfg.relay.request_timeout_ms).toBe(30_000);
    expect(cfg.relay.nonce_ttl_ms).toBe(60_000);
    expect(cfg.broker.session_ttl_ms).toBe(300_000);
    expect(cfg.broker.providers).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// loadConfig with a real YAML file
// ---------------------------------------------------------------------------

describe("loadConfig", () => {
  const tmpPath = join(process.cwd(), "test-relay-config.yaml");

  afterEach(() => {
    vi.unstubAllEnvs();
    try {
      unlinkSync(tmpPath);
    } catch {
      // ignore
    }
  });

  it("loads YAML and resolves ${ENV_VAR} patterns", () => {
    writeFileSync(
      tmpPath,
      `
server:
  port: 9999
  base_url: http://test:9999
broker:
  providers:
    slack:
      client_id: \${TEST_SLACK_ID}
      pkce: true
      scopes: [channels:read]
`,
    );

    const cfg = loadConfig({
      RELAY_CONFIG: tmpPath,
      TEST_SLACK_ID: "xoxb-resolved",
    });
    expect(cfg.server.port).toBe(9999);
    expect(cfg.broker.providers.slack?.client_id).toBe("xoxb-resolved");
  });

  it("resolves unset env vars to empty string", () => {
    writeFileSync(
      tmpPath,
      `
broker:
  providers:
    github:
      client_id: \${UNSET_VAR_12345}
      pkce: true
      scopes: [user]
`,
    );

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.broker.providers.github?.client_id).toBe("");
  });

  it("applies Zod defaults for missing sections", () => {
    writeFileSync(tmpPath, "server:\n  port: 7777\n");

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.port).toBe(7777);
    expect(cfg.relay.ping_interval_ms).toBe(30_000); // default
    expect(cfg.broker.session_ttl_ms).toBe(300_000); // default
  });

  it("derives base_url from port when empty", () => {
    writeFileSync(tmpPath, "server:\n  port: 4444\n");

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.base_url).toBe("http://localhost:4444");
  });

  it("throws when config file does not exist", () => {
    expect(() => loadConfig({ RELAY_CONFIG: "/nonexistent/relay.yaml" })).toThrow(
      "Config file not found",
    );
  });
});

// ---------------------------------------------------------------------------
// buildProviderMap
// ---------------------------------------------------------------------------

describe("buildProviderMap", () => {
  it("skips providers with empty client_id", () => {
    const cfg = defaultConfig();
    cfg.broker.providers = {
      slack: { client_id: "", pkce: true, scopes: ["channels:read"] },
      github: { client_id: "gh-123", pkce: true, scopes: ["user"] },
    };
    const map = buildProviderMap(cfg);
    expect(map.size).toBe(1);
    expect(map.has("github")).toBe(true);
    expect(map.has("slack")).toBe(false);
  });

  it("includes client_secret when present", () => {
    const cfg = defaultConfig();
    cfg.broker.providers = {
      github: {
        client_id: "gh-123",
        client_secret: "gh-secret",
        pkce: true,
        scopes: ["user"],
      },
    };
    const map = buildProviderMap(cfg);
    expect(map.get("github")?.clientSecret).toBe("gh-secret");
  });

  it("omits client_secret when empty", () => {
    const cfg = defaultConfig();
    cfg.broker.providers = {
      slack: { client_id: "sl-123", client_secret: "", pkce: true, scopes: [] },
    };
    const map = buildProviderMap(cfg);
    expect(map.get("slack")?.clientSecret).toBeUndefined();
  });

  it("returns empty map for no providers", () => {
    const cfg = defaultConfig();
    const map = buildProviderMap(cfg);
    expect(map.size).toBe(0);
  });
});
