/**
 * CLI bin smoke tests.
 *
 * Spawns the compiled bin (or its TS source via tsx) as a subprocess and
 * verifies that `--check` exits 0 for a valid fixture and non-zero for an
 * invalid one. These do not bind any port — `--check` forwards to
 * `startServer({ dryRun: true })`.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const BIN_SOURCE = join(REPO_ROOT, "src", "index.ts");

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(args: readonly string[], env: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    // Use the locally installed `tsx` to run the TypeScript source directly so
    // we don't depend on `npm run build` having been invoked first.
    const child = spawn(process.execPath, ["--import", "tsx", BIN_SOURCE, ...args], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));
    child.stderr.on("data", (c: Buffer) => stderrChunks.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? -1,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });
  });
}

describe("dicode-relay --check", () => {
  let dir: string;
  let configPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "dicode-relay-cli-"));
    configPath = join(dir, "relay.yaml");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("exits 0 for a valid config", async () => {
    writeFileSync(
      configPath,
      `
server:
  port: 5553
status:
  password: test-pw
broker:
  signing_key_file: ""
`,
    );

    const { code, stdout } = await runCli(["--check", "--config", configPath]);
    expect(code).toBe(0);
    expect(stdout).toContain("config OK");
  }, 30_000);

  it("exits non-zero for a missing config file", async () => {
    const missing = join(dir, "does-not-exist.yaml");
    const { code, stderr } = await runCli(["--check", "--config", missing]);
    expect(code).not.toBe(0);
    expect(stderr).toContain("config check failed");
  }, 30_000);

  it("exits non-zero when signing_key_file points at a missing file", async () => {
    // Operator-trusted YAML path: `--check` must surface a clear error so
    // typo'd `signing_key_file` paths are caught at config-validation time
    // rather than silently auto-generating at the wrong location (which
    // would rotate the broker pubkey and break TOFU-pinned daemons —
    // see issue #54 for the broader hardening plan).
    const target = join(dir, "nonexistent-dir", "broker-signing.key");
    writeFileSync(
      configPath,
      `
broker:
  signing_key_file: ${target}
`,
    );

    const { code, stderr } = await runCli(["--check", "--config", configPath]);
    expect(code).not.toBe(0);
    expect(stderr).toMatch(/broker\.signing_key_file points to a missing file/);
  }, 30_000);
});
