/**
 * Config loading tests — env resolution, Zod defaults, provider building.
 */

import { writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ZodError } from "zod";
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
    expect(cfg.relay.max_pending_per_client).toBe(256);
    expect(cfg.relay.max_buffered_bytes).toBe(16 * 1024 * 1024);
    expect(cfg.relay.max_body_bytes).toBe(5 * 1024 * 1024);
    expect(cfg.broker.session_ttl_ms).toBe(300_000);
    expect(cfg.broker.providers).toEqual({});
  });

  it("defaults the mTLS control-channel listener to port 5554 with no cert files", () => {
    const cfg = defaultConfig();
    expect(cfg.server.mtls.port).toBe(5554);
    expect(cfg.server.mtls.cert_file).toBe("");
    expect(cfg.server.mtls.key_file).toBe("");
  });

  it("defaults server.multi_instance to false (single-instance auto-generate)", () => {
    expect(defaultConfig().server.multi_instance).toBe(false);
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

  it("parses server.multi_instance: true from YAML", () => {
    writeFileSync(tmpPath, "server:\n  multi_instance: true\n");

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.multi_instance).toBe(true);
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

  it("parses server.mtls settings from YAML", () => {
    writeFileSync(
      tmpPath,
      `
server:
  port: 9999
  mtls:
    port: 6001
    cert_file: /etc/relay/mtls-cert.pem
    key_file: /etc/relay/mtls-key.pem
`,
    );

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.mtls.port).toBe(6001);
    expect(cfg.server.mtls.cert_file).toBe("/etc/relay/mtls-cert.pem");
    expect(cfg.server.mtls.key_file).toBe("/etc/relay/mtls-key.pem");
  });

  it("applies mtls defaults for keys omitted from a partial mtls block", () => {
    writeFileSync(tmpPath, "server:\n  mtls:\n    port: 6002\n");

    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.mtls.port).toBe(6002);
    expect(cfg.server.mtls.cert_file).toBe("");
    expect(cfg.server.mtls.key_file).toBe("");
  });

  it("throws when config file does not exist", () => {
    expect(() => loadConfig({ RELAY_CONFIG: "/nonexistent/relay.yaml" })).toThrow(
      "Config file not found",
    );
  });

  // ---------------------------------------------------------------------------
  // Security-critical fields reject empty values at load time
  // ---------------------------------------------------------------------------
  //
  // resolveEnvVars collapses unresolved `${VAR}` placeholders to "" and warns.
  // For provider client_id / client_secret that's by design (silently disables
  // the provider). For status.password and server.base_url it's a silent
  // misconfiguration that breaks security (public dashboard) or functionality
  // (broken OAuth callbacks). Zod's .min(1) rejects at parse time with a
  // clear message naming the field — fail closed before HTTP routes mount.

  it("rejects unresolved ${STATUS_PASSWORD} with a clear ZodError", () => {
    writeFileSync(
      tmpPath,
      `
status:
  password: \${STATUS_PASSWORD}
`,
    );

    let caught: unknown;
    try {
      loadConfig({ RELAY_CONFIG: tmpPath });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ZodError);
    const msg = (caught as ZodError).issues.map((i) => i.message).join("\n");
    expect(msg).toContain("status.password must be non-empty");
    expect(msg).toMatch(/STATUS_PASSWORD/);
    // Path on the issue must name the offending field
    const paths = (caught as ZodError).issues.map((i) => i.path.join("."));
    expect(paths).toContain("status.password");
  });

  it("rejects literal empty status.password in YAML", () => {
    writeFileSync(tmpPath, 'status:\n  password: ""\n');
    expect(() => loadConfig({ RELAY_CONFIG: tmpPath })).toThrow(ZodError);
  });

  it("accepts an omitted status section (dashboard disabled, /status returns 404)", () => {
    writeFileSync(tmpPath, "server:\n  port: 5555\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.status.password).toBeUndefined();
  });

  it("accepts a YAML `password:` (null) and treats it as absent", () => {
    // js-yaml parses `password:` with no value as `null`. .optional() would
    // reject this with a generic Zod error; .nullish().transform() maps null
    // back to undefined so it falls through to the documented "omit to
    // disable" default (statusAuth(undefined) → 404).
    writeFileSync(tmpPath, "status:\n  password:\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.status.password).toBeUndefined();
  });

  it("accepts an explicit `password: null` and treats it as absent", () => {
    writeFileSync(tmpPath, "status:\n  password: null\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.status.password).toBeUndefined();
  });

  it("accepts a YAML `password: ~` (null) and treats it as absent", () => {
    writeFileSync(tmpPath, "status:\n  password: ~\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.status.password).toBeUndefined();
  });

  it('rejects `password: "${STATUS_PASSWORD}"` when STATUS_PASSWORD is unset (resolves to "")', () => {
    // Same as the ${STATUS_PASSWORD} reproducer above, but with the value
    // explicitly quoted in YAML — the env interpolation still collapses to
    // "" and Zod's .min(1) check fires with the curated message.
    writeFileSync(tmpPath, 'status:\n  password: "${STATUS_PASSWORD}"\n');
    let caught: unknown;
    try {
      loadConfig({ RELAY_CONFIG: tmpPath });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ZodError);
    const msg = (caught as ZodError).issues.map((i) => i.message).join("\n");
    expect(msg).toContain("status.password must be non-empty");
  });

  it("rejects unresolved ${BASE_URL} with a clear ZodError", () => {
    writeFileSync(
      tmpPath,
      `
server:
  port: 5553
  base_url: \${BASE_URL}
`,
    );

    let caught: unknown;
    try {
      loadConfig({ RELAY_CONFIG: tmpPath });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ZodError);
    const msg = (caught as ZodError).issues.map((i) => i.message).join("\n");
    expect(msg).toContain("server.base_url must be non-empty");
    expect(msg).toMatch(/BASE_URL/);
    const paths = (caught as ZodError).issues.map((i) => i.path.join("."));
    expect(paths).toContain("server.base_url");
  });

  it("rejects literal empty server.base_url in YAML", () => {
    writeFileSync(tmpPath, 'server:\n  port: 5553\n  base_url: ""\n');
    expect(() => loadConfig({ RELAY_CONFIG: tmpPath })).toThrow(ZodError);
  });

  it("accepts an omitted base_url and falls back to http://localhost:<port>", () => {
    writeFileSync(tmpPath, "server:\n  port: 6666\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.base_url).toBe("http://localhost:6666");
  });

  it("accepts a YAML `base_url:` (null) and falls back to localhost", () => {
    // js-yaml parses `base_url:` with no value as `null`. .nullish() maps it
    // to undefined so the outer transform's localhost fallback fires.
    writeFileSync(tmpPath, "server:\n  port: 7777\n  base_url:\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.base_url).toBe("http://localhost:7777");
  });

  it("accepts an explicit `base_url: null` and falls back to localhost", () => {
    writeFileSync(tmpPath, "server:\n  port: 8888\n  base_url: null\n");
    const cfg = loadConfig({ RELAY_CONFIG: tmpPath });
    expect(cfg.server.base_url).toBe("http://localhost:8888");
  });

  it('rejects `base_url: "${BASE_URL}"` when BASE_URL is unset (resolves to "")', () => {
    writeFileSync(tmpPath, 'server:\n  port: 5553\n  base_url: "${BASE_URL}"\n');
    let caught: unknown;
    try {
      loadConfig({ RELAY_CONFIG: tmpPath });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ZodError);
    const msg = (caught as ZodError).issues.map((i) => i.message).join("\n");
    expect(msg).toContain("server.base_url must be non-empty");
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
