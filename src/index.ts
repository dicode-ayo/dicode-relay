#!/usr/bin/env node
/**
 * dicode-relay CLI bin.
 *
 * Parses `--config <path>` and `--check` from `process.argv`, then delegates
 * to the programmatic `startServer` entry point (`./start.js`).
 *
 *   dicode-relay [--config <path>]   # start the relay server
 *   dicode-relay --check [--config <path>]  # validate config + wiring, exit 0/non-zero
 *
 * SIGTERM/SIGINT trigger a graceful `handle.close()` and exit 0. Library
 * callers that import `startServer` directly own their own lifecycle —
 * signal handling lives here, not in `start.ts`.
 */

import { startServer, type StartOpts } from "./start.js";

function parseArgs(argv: readonly string[]): { configPath: string | undefined; check: boolean } {
  let configPath: string | undefined;
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--config" && i + 1 < argv.length) {
      configPath = argv[i + 1];
      i++;
    } else if (arg === "--check") {
      check = true;
    }
  }
  return { configPath, check };
}

async function main(): Promise<void> {
  const { configPath, check } = parseArgs(process.argv.slice(2));

  // Build StartOpts conditionally so we don't pass `configPath: undefined`
  // under exactOptionalPropertyTypes.
  const baseOpts: StartOpts = configPath !== undefined ? { configPath } : {};

  if (check) {
    try {
      const handle = await startServer({ ...baseOpts, dryRun: true });
      await handle.close();
      console.log("dicode-relay: config OK");
      process.exit(0);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`dicode-relay: config check failed: ${msg}`);
      process.exit(1);
    }
  }

  const handle = await startServer(baseOpts);

  const shutdown = (signal: string): void => {
    console.log(`${signal} received, shutting down`);
    handle
      .close()
      .then(() => {
        process.exit(0);
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`shutdown error: ${msg}`);
        process.exit(1);
      });
  };

  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });
  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`dicode-relay: fatal error: ${msg}`);
  process.exit(1);
});
