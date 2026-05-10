/**
 * Tests for the programmatic `startServer` entry point.
 *
 * Four dryRun cases (no ports involved) verify that each failure surface
 * (config loader, signing key, provider/grant/broker wiring) surfaces a clean
 * rejected promise. One real-listen smoke verifies that a non-dryRun call
 * binds, serves /health, and releases the port on close().
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, get as httpGet } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startServer } from "../src/start.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

interface FixtureContext {
  dir: string;
  configPath: string;
}

function makeFixture(): FixtureContext {
  const dir = mkdtempSync(join(tmpdir(), "dicode-relay-start-"));
  return { dir, configPath: join(dir, "relay.yaml") };
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

  it("resolves cleanly for a minimal valid config", async () => {
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
      env: { ...process.env, HOME: ctx.dir },
      dryRun: true,
    });

    expect(handle.httpServer.listening).toBe(false);
    expect(handle.relayServer).toBeDefined();

    // close() must be a safe no-op against the unbound socket.
    await expect(handle.close()).resolves.toBeUndefined();
  });

  it("rejects on malformed YAML", async () => {
    writeYaml(ctx, "server:\n  port: 5553\n  base_url: [unclosed\n");

    await expect(
      startServer({
        configPath: ctx.configPath,
        env: { ...process.env },
        dryRun: true,
      }),
    ).rejects.toThrow();
  });

  it("loads when a referenced ${VAR} resolves to empty (provider silently skipped)", async () => {
    // Empty client_id collapses to a disabled provider — same as legacy
    // env-var-based setup. This is not an error; the relay starts fine.
    writeYaml(
      ctx,
      `
broker:
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

  it("rejects when signing_key_file points at an unwritable/unreadable path", async () => {
    // /proc/<pid>/cant-write-here is a synthetic path that does not exist
    // and cannot be created (/proc subdirs are kernel-managed). Forces the
    // PEM read in loadBrokerSigningKey to throw ENOENT, exercising the disk
    // failure surface that dryRun is supposed to catch early.
    writeYaml(
      ctx,
      `
broker:
  signing_key_file: /proc/1/cant-write-here/broker-signing.key
`,
    );

    await expect(
      startServer({
        configPath: ctx.configPath,
        env: { ...process.env },
        dryRun: true,
      }),
    ).rejects.toThrow();
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

  it("binds the configured port, serves /health, releases on close()", async () => {
    const port = await pickPort();
    writeYaml(
      ctx,
      `
server:
  port: ${String(port)}
  base_url: http://localhost:${String(port)}
status:
  password: test-pw
`,
    );

    const handle = await startServer({
      configPath: ctx.configPath,
      env: { ...process.env },
    });

    try {
      expect(handle.httpServer.listening).toBe(true);
      const { status, body } = await httpGetBody(port, "/health");
      expect(status).toBe(200);
      expect(JSON.parse(body)).toEqual({ ok: true });
    } finally {
      await handle.close();
    }

    expect(handle.httpServer.listening).toBe(false);

    // After close(), a fresh listen on the same port must succeed —
    // proves the socket was released cleanly.
    await new Promise<void>((resolve, reject) => {
      const probe = createHttpServer();
      probe.once("error", reject);
      probe.listen(port, () => {
        probe.close(() => {
          resolve();
        });
      });
    });
  });
});
