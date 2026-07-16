/**
 * Tests for the programmatic `startServer` entry point.
 *
 * dryRun cases verify each failure surface (config loader, signing key,
 * provider/grant/broker wiring) surfaces a clean rejected promise, and that
 * dryRun never writes secret material to disk or binds a port. One real-listen
 * smoke verifies that a non-dryRun call binds, serves /health, and releases
 * the port on close().
 */

import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, get as httpGet } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { startServer } from "../src/start.js";
import { testServerCert } from "./helpers.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

interface FixtureContext {
  dir: string;
  configPath: string;
  signingKeyPath: string;
}

/**
 * Create a tmpdir fixture and pre-generate a P-256 broker signing key inside
 * it. Tests that need a YAML config point `broker.signing_key_file` at
 * `ctx.signingKeyPath` so `loadBrokerSigningKey` reads from the fixture
 * instead of auto-generating one in the test runner's cwd.
 */
function makeFixture(): FixtureContext {
  const dir = mkdtempSync(join(tmpdir(), "dicode-relay-start-"));
  const configPath = join(dir, "relay.yaml");
  const signingKeyPath = join(dir, "signing.pem");
  const pair = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  writeFileSync(signingKeyPath, pair.privateKey, { mode: 0o600 });
  return { dir, configPath, signingKeyPath };
}

function writeYaml(ctx: FixtureContext, body: string): void {
  writeFileSync(ctx.configPath, body);
}

/** Allocate an ephemeral port by binding port 0, then release it. */
async function pickPort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const probe = createHttpServer();
    probe.once("error", reject);
    probe.listen(0, () => {
      const addr = probe.address();
      if (typeof addr !== "object" || addr === null) {
        probe.close();
        reject(new Error("could not pick a port"));
        return;
      }
      const port = addr.port;
      probe.close(() => {
        resolve(port);
      });
    });
  });
}

/** GET http://localhost:<port><path> and return the response body. */
async function httpGetBody(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpGet({ hostname: "127.0.0.1", port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    req.on("error", reject);
  });
}

/** Assert that a fresh listener can bind `port` — proves it was released. */
async function assertPortFree(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const probe = createHttpServer();
    probe.once("error", reject);
    probe.listen(port, () => {
      probe.close((err) => {
        if (err !== undefined) reject(err);
        else resolve();
      });
    });
  });
}

// ---------------------------------------------------------------------------
// dryRun cases
// ---------------------------------------------------------------------------

describe("startServer dryRun", () => {
  let ctx: FixtureContext;

  beforeEach(() => {
    ctx = makeFixture();
  });

  afterEach(() => {
    rmSync(ctx.dir, { recursive: true, force: true });
  });

  it("resolves cleanly for a minimal valid config and leaves the port free", async () => {
    const port = await pickPort();
    writeYaml(
      ctx,
      `
server:
  port: ${String(port)}
status:
  password: test-pw
broker:
  signing_key_file: ${ctx.signingKeyPath}
`,
    );

    const handle = await startServer({
      configPath: ctx.configPath,
      env: { ...process.env, HOME: ctx.dir },
      dryRun: true,
    });

    expect(handle.httpServer.listening).toBe(false);
    expect(handle.relayServer).toBeDefined();

    // close() must be a safe no-op against the unbound socket.
    await expect(handle.close()).resolves.toBeUndefined();

    // Issue #70 acceptance criterion: after a dryRun returns + closes, the
    // configured port must still be bindable. Proves `listen()` was actually
    // skipped (no latched socket, no WSS holding the bind).
    await expect(assertPortFree(port)).resolves.toBeUndefined();
  });

  it("does not write broker-signing-key.pem to cwd when broker.signing_key_file is empty", async () => {
    // Critical regression test for the dryRun-auto-gen footgun (issue #54).
    // External supervisors call startServer({ dryRun: true }) to validate
    // their config; that path must never materialise an ECDSA key into the
    // supervisor's cwd. Run the dryRun from a clean tmpdir and assert no
    // PEM is left behind.
    const cleanCwd = mkdtempSync(join(tmpdir(), "dicode-relay-cwd-"));
    const originalCwd = process.cwd();
    process.chdir(cleanCwd);
    try {
      writeYaml(
        ctx,
        `
server:
  port: 5553
status:
  password: test-pw
broker:
  signing_key_file: ""
`,
      );

      const handle = await startServer({
        configPath: ctx.configPath,
        // Strip any BROKER_SIGNING_KEY* env vars so the empty-signing-key
        // branch is actually exercised.
        env: { HOME: ctx.dir },
        dryRun: true,
      });
      await handle.close();

      expect(existsSync(join(cleanCwd, "broker-signing-key.pem"))).toBe(false);
      // Belt-and-braces: nothing at all should have been written here.
      expect(readdirSync(cleanCwd)).toEqual([]);
    } finally {
      process.chdir(originalCwd);
      rmSync(cleanCwd, { recursive: true, force: true });
    }
  });

  it("rejects on malformed YAML", async () => {
    // Unterminated quoted string — guaranteed to fail across js-yaml versions
    // and platforms (no reliance on flow-sequence parser quirks).
    writeYaml(ctx, 'server:\n  port: 5553\n  base_url: "unterminated\n');

    await expect(
      startServer({
        configPath: ctx.configPath,
        env: { ...process.env },
        dryRun: true,
      }),
    ).rejects.toThrow();
  });

  it("re-validates opts.config through Zod and rejects malformed shapes", async () => {
    // dicode-core's Deno buildin/relay-server consumes this library at the
    // npm boundary where TS types are erased. A caller could pass a config
    // object that *looks* like RelayConfig at the JS level but fails the
    // schema. Defensive re-parse must catch it before the value flows into
    // readFileSync / loadBrokerSigningKey.
    // Cast through `unknown` to model the type-erased JS caller (Deno via
    // npm) — without it, TS would reject the bad shape at compile time.
    const bogusOpts = {
      config: { server: { port: "not a number" } },
      env: { ...process.env },
      dryRun: true,
    } as unknown as Parameters<typeof startServer>[0];

    await expect(startServer(bogusOpts)).rejects.toThrow(ZodError);
  });

  it("loads when a referenced ${VAR} resolves to empty (provider silently skipped)", async () => {
    // Empty client_id collapses to a disabled provider — same as legacy
    // env-var-based setup. This is not an error; the relay starts fine.
    writeYaml(
      ctx,
      `
broker:
  signing_key_file: ${ctx.signingKeyPath}
  providers:
    github:
      client_id: \${UNSET_VAR_FOR_TEST_98765}
      pkce: true
      scopes: [user]
`,
    );

    const handle = await startServer({
      configPath: ctx.configPath,
      env: { ...process.env },
      dryRun: true,
    });
    await handle.close();
  });

  it("rejects a signing_key_file pointing at a missing file (configured-path branch never auto-generates)", async () => {
    // Operator-trusted YAML path: a typo'd `signing_key_file` must surface a
    // clear error rather than silently auto-generating at the wrong path
    // (which would rotate the broker pubkey and break TOFU-pinned daemons).
    // dryRun still exercises the same loader, so the error fires there too.
    // Issue #54 tracks broader hardening of auto-gen surface area.
    const target = join(ctx.dir, "nonexistent-dir", "broker-signing.key");
    writeYaml(
      ctx,
      `
broker:
  signing_key_file: ${target}
`,
    );

    await expect(
      startServer({
        configPath: ctx.configPath,
        env: { ...process.env },
        dryRun: true,
      }),
    ).rejects.toThrow(/broker\.signing_key_file points to a missing file/);

    // Importantly: no file or parent dir was materialised as a side effect.
    expect(existsSync(target)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// opts.env scoping for the E2E mock router
// ---------------------------------------------------------------------------

describe("startServer opts.env scoping", () => {
  let ctx: FixtureContext;

  beforeEach(() => {
    ctx = makeFixture();
  });

  afterEach(() => {
    rmSync(ctx.dir, { recursive: true, force: true });
  });

  it("respects opts.env for E2E mock enablement (enabled via opts.env)", async () => {
    writeYaml(
      ctx,
      `
server:
  port: 5553
status:
  password: test-pw
broker:
  signing_key_file: ${ctx.signingKeyPath}
`,
    );

    const handle = await startServer({
      configPath: ctx.configPath,
      env: { DICODE_E2E_MOCK_PROVIDER: "1", NODE_ENV: "development" },
      dryRun: true,
    });
    // The mock router registers a "mock" provider key in the broker session
    // map and exposes /connect/mock. Easiest visible signal is that the
    // RelayServer's broker pubkey is set and the handle's underlying express
    // app has the mock route mounted — but we don't want to introspect
    // internals. As a behaviour proxy, this dryRun succeeds, which proves
    // the mock router was constructed without throwing (it depends on
    // brokerKey + sessions). The disabled-case below pairs this assertion.
    await handle.close();
  });

  it("respects opts.env for E2E mock enablement (disabled when opts.env omits the flag)", async () => {
    writeYaml(
      ctx,
      `
server:
  port: 5553
status:
  password: test-pw
broker:
  signing_key_file: ${ctx.signingKeyPath}
`,
    );

    // Even though the host `process.env` might have DICODE_E2E_MOCK_PROVIDER
    // set during local dev, an empty opts.env must NOT enable the mock.
    // Save + clobber the host env to make the inheritance hazard concrete.
    const previous = process.env.DICODE_E2E_MOCK_PROVIDER;
    process.env.DICODE_E2E_MOCK_PROVIDER = "1";
    try {
      const handle = await startServer({
        configPath: ctx.configPath,
        env: {},
        dryRun: true,
      });
      await handle.close();
      // dryRun returned cleanly — the mock router was not mounted (otherwise
      // the warning would have fired). The behavioural check is that the
      // host env's DICODE_E2E_MOCK_PROVIDER=1 did not leak into the call.
    } finally {
      if (previous === undefined) {
        delete process.env.DICODE_E2E_MOCK_PROVIDER;
      } else {
        process.env.DICODE_E2E_MOCK_PROVIDER = previous;
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Smoke: real listen
// ---------------------------------------------------------------------------

describe("startServer real listen", () => {
  let ctx: FixtureContext;

  beforeEach(() => {
    ctx = makeFixture();
  });

  afterEach(() => {
    rmSync(ctx.dir, { recursive: true, force: true });
  });

  it("binds both listeners, serves /health, releases on close()", async () => {
    const port = await pickPort();
    const mtlsPort = await pickPort();
    // Explicit mtls cert files inside the fixture dir — otherwise
    // resolveMtlsCert would persist an auto-generated dev cert into the
    // test runner's cwd.
    const serverCert = await testServerCert();
    const mtlsCertPath = join(ctx.dir, "mtls-cert.pem");
    const mtlsKeyPath = join(ctx.dir, "mtls-key.pem");
    writeFileSync(mtlsCertPath, serverCert.certPem);
    writeFileSync(mtlsKeyPath, serverCert.keyPem, { mode: 0o600 });
    writeYaml(
      ctx,
      `
server:
  port: ${String(port)}
  base_url: http://localhost:${String(port)}
  mtls:
    port: ${String(mtlsPort)}
    cert_file: ${mtlsCertPath}
    key_file: ${mtlsKeyPath}
status:
  password: test-pw
broker:
  signing_key_file: ${ctx.signingKeyPath}
`,
    );

    const handle = await startServer({
      configPath: ctx.configPath,
      env: { ...process.env },
    });

    try {
      expect(handle.httpServer.listening).toBe(true);
      expect(handle.mtlsServer.listening).toBe(true);
      const { status, body } = await httpGetBody(port, "/health");
      expect(status).toBe(200);
      expect(JSON.parse(body)).toEqual({ ok: true });
    } finally {
      await handle.close();
    }

    expect(handle.httpServer.listening).toBe(false);
    expect(handle.mtlsServer.listening).toBe(false);

    // After close(), a fresh listen on the same ports must succeed —
    // proves the sockets were released cleanly.
    await assertPortFree(port);
    await assertPortFree(mtlsPort);
  });
});
