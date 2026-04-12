#!/usr/bin/env node
// Copy non-TS assets (currently: SQL migration files) into `dist/` so the
// compiled code can find them via `fileURLToPath(import.meta.url)`.

import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/db/migrations");
const dst = resolve(root, "dist/src/db/migrations");

if (!existsSync(src)) {
  console.error(`copy-assets: source ${src} does not exist`);
  process.exit(1);
}

mkdirSync(dirname(dst), { recursive: true });
cpSync(src, dst, { recursive: true });
console.log(`copy-assets: copied ${src} -> ${dst}`);
