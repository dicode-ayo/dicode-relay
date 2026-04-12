/**
 * SQLite persistence layer for dicode-relay.
 *
 * Exposes a small typed API (`Db`) backed by `better-sqlite3`. Callers never
 * see raw SQL or the underlying `Database` handle — this keeps the persistence
 * boundary narrow and easy to port to Postgres later.
 *
 * The database file path is resolved from `DICODE_RELAY_DB` with a dev-friendly
 * fallback of `./data/relay.db`. The production Dockerfile mounts
 * `/var/lib/dicode/relay.db`.
 */

import Database from "better-sqlite3";
import type { Database as BetterSqliteDatabase, Statement } from "better-sqlite3";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type Tier = "free" | "pro" | "team";

export interface GithubProfile {
  githubId: number;
  login: string;
  email?: string | null;
}

export interface User {
  id: number;
  githubId: number;
  githubLogin: string;
  email: string | null;
  githubAccessTokenEncrypted: Buffer | null;
  createdAt: number;
}

export interface DaemonRow {
  uuid: string;
  userId: number;
  label: string | null;
  firstSeen: number;
  lastSeen: number;
}

export interface Plan {
  userId: number;
  tier: Tier;
  hookQuotaMonthly: number;
  concurrentDaemons: number;
  oauthProviders: string[] | "*";
  stripeSubId: string | null;
  renewsAt: number | null;
}

export interface Db {
  // users
  upsertUserFromGithub(gh: GithubProfile, token?: Buffer): User;
  getUserById(id: number): User | null;

  // daemons
  getDaemon(uuid: string): DaemonRow | null;
  claimDaemon(uuid: string, userId: number, label?: string): void;
  countActiveDaemonsForUser(userId: number, uuids: Iterable<string>): number;

  // plans
  getPlan(userId: number): Plan;
  setPlan(userId: number, tier: Tier): void;

  // usage
  incrementHookUsage(userId: number, period: string): number;

  // lifecycle
  close(): void;
}

// ---------------------------------------------------------------------------
// Plan tier defaults
// ---------------------------------------------------------------------------

interface PlanDefaults {
  hookQuotaMonthly: number;
  concurrentDaemons: number;
  oauthProviders: string[] | "*";
}

const PLAN_DEFAULTS: Record<Tier, PlanDefaults> = {
  free: { hookQuotaMonthly: 1_000, concurrentDaemons: 1, oauthProviders: ["github"] },
  pro: { hookQuotaMonthly: 50_000, concurrentDaemons: 3, oauthProviders: "*" },
  team: { hookQuotaMonthly: 500_000, concurrentDaemons: 10, oauthProviders: "*" },
};

// ---------------------------------------------------------------------------
// Row shapes as returned by better-sqlite3 (internal — never leak out)
// ---------------------------------------------------------------------------

interface UserRow {
  id: number;
  github_id: number;
  github_login: string;
  email: string | null;
  github_access_token_encrypted: Buffer | null;
  created_at: number;
}

interface DaemonSqlRow {
  uuid: string;
  user_id: number;
  label: string | null;
  first_seen: number;
  last_seen: number;
}

interface PlanRow {
  user_id: number;
  tier: Tier;
  hook_quota_monthly: number;
  concurrent_daemons: number;
  oauth_providers: string;
  stripe_sub_id: string | null;
  renews_at: number | null;
}

interface HookUsageRow {
  count: number;
}

interface SchemaVersionRow {
  version: number;
}

interface DaemonUuidOnlyRow {
  uuid: string;
}

interface PragmaForeignKeysRow {
  foreign_keys: number;
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

const MIGRATION_FILE_RE = /^(\d{3})_[a-z0-9_]+\.sql$/;

function migrationsDir(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return join(dirname(thisFile), "migrations");
}

function runMigrations(db: BetterSqliteDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER PRIMARY KEY
    );
  `);

  const applied = new Set(
    (db.prepare("SELECT version FROM schema_version").all() as SchemaVersionRow[]).map(
      (r) => r.version,
    ),
  );

  const dir = migrationsDir();
  const files = readdirSync(dir)
    .filter((f) => MIGRATION_FILE_RE.test(f))
    .sort();

  for (const file of files) {
    const match = MIGRATION_FILE_RE.exec(file);
    if (!match) continue;
    const versionStr = match[1];
    if (versionStr === undefined) continue;
    const version = Number.parseInt(versionStr, 10);
    if (applied.has(version)) continue;

    const sql = readFileSync(join(dir, file), "utf8");
    const tx = db.transaction(() => {
      db.exec(sql);
      db.prepare("INSERT INTO schema_version (version) VALUES (?)").run(version);
    });
    tx();
  }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

function resolveDbPath(explicit?: string): string {
  if (explicit !== undefined && explicit !== "") return explicit;
  const fromEnv = process.env.DICODE_RELAY_DB;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  return join(process.cwd(), "data", "relay.db");
}

// ---------------------------------------------------------------------------
// Row mappers
// ---------------------------------------------------------------------------

function mapUser(row: UserRow): User {
  return {
    id: row.id,
    githubId: row.github_id,
    githubLogin: row.github_login,
    email: row.email,
    githubAccessTokenEncrypted: row.github_access_token_encrypted,
    createdAt: row.created_at,
  };
}

function mapDaemon(row: DaemonSqlRow): DaemonRow {
  return {
    uuid: row.uuid,
    userId: row.user_id,
    label: row.label,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
  };
}

function parseOauthProviders(raw: string): string[] | "*" {
  if (raw === "*") return "*";
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed) || !parsed.every((v): v is string => typeof v === "string")) {
    throw new Error(`plans.oauth_providers is malformed: ${raw}`);
  }
  return parsed;
}

function serializeOauthProviders(value: string[] | "*"): string {
  return value === "*" ? "*" : JSON.stringify(value);
}

function mapPlan(row: PlanRow): Plan {
  return {
    userId: row.user_id,
    tier: row.tier,
    hookQuotaMonthly: row.hook_quota_monthly,
    concurrentDaemons: row.concurrent_daemons,
    oauthProviders: parseOauthProviders(row.oauth_providers),
    stripeSubId: row.stripe_sub_id,
    renewsAt: row.renews_at,
  };
}

// ---------------------------------------------------------------------------
// Db implementation
// ---------------------------------------------------------------------------

interface Statements {
  upsertUser: Statement<[number, string, string | null, Buffer | null, number]>;
  getUserByGithubId: Statement<[number]>;
  getUserById: Statement<[number]>;
  getDaemon: Statement<[string]>;
  claimDaemon: Statement<[string, number, string | null, number, number]>;
  listDaemonUuidsForUser: Statement<[number]>;
  getPlan: Statement<[number]>;
  upsertPlan: Statement<[number, Tier, number, number, string, string | null, number | null]>;
  getHookUsage: Statement<[number, string]>;
  incrementHookUsage: Statement<[number, string]>;
}

class SqliteDb implements Db {
  private readonly handle: BetterSqliteDatabase;
  private readonly stmts: Statements;

  constructor(handle: BetterSqliteDatabase) {
    this.handle = handle;
    this.stmts = {
      upsertUser: handle.prepare(
        `INSERT INTO users (github_id, github_login, email, github_access_token_encrypted, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(github_id) DO UPDATE SET
           github_login = excluded.github_login,
           email = excluded.email,
           github_access_token_encrypted =
             COALESCE(excluded.github_access_token_encrypted, users.github_access_token_encrypted)`,
      ),
      getUserByGithubId: handle.prepare("SELECT * FROM users WHERE github_id = ?"),
      getUserById: handle.prepare("SELECT * FROM users WHERE id = ?"),
      getDaemon: handle.prepare("SELECT * FROM daemons WHERE uuid = ?"),
      claimDaemon: handle.prepare(
        `INSERT INTO daemons (uuid, user_id, label, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(uuid) DO UPDATE SET
           user_id = excluded.user_id,
           label = COALESCE(excluded.label, daemons.label),
           last_seen = excluded.last_seen`,
      ),
      listDaemonUuidsForUser: handle.prepare("SELECT uuid FROM daemons WHERE user_id = ?"),
      getPlan: handle.prepare("SELECT * FROM plans WHERE user_id = ?"),
      upsertPlan: handle.prepare(
        `INSERT INTO plans (user_id, tier, hook_quota_monthly, concurrent_daemons, oauth_providers, stripe_sub_id, renews_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           tier = excluded.tier,
           hook_quota_monthly = excluded.hook_quota_monthly,
           concurrent_daemons = excluded.concurrent_daemons,
           oauth_providers = excluded.oauth_providers`,
      ),
      getHookUsage: handle.prepare("SELECT count FROM hook_usage WHERE user_id = ? AND period = ?"),
      incrementHookUsage: handle.prepare(
        `INSERT INTO hook_usage (user_id, period, count)
         VALUES (?, ?, 1)
         ON CONFLICT(user_id, period) DO UPDATE SET count = hook_usage.count + 1`,
      ),
    };
  }

  upsertUserFromGithub(gh: GithubProfile, token?: Buffer): User {
    const now = Math.floor(Date.now() / 1000);
    const email = gh.email ?? null;
    const tokenBuf = token ?? null;
    const tx = this.handle.transaction(() => {
      this.stmts.upsertUser.run(gh.githubId, gh.login, email, tokenBuf, now);
      const row = this.stmts.getUserByGithubId.get(gh.githubId) as UserRow | undefined;
      if (row === undefined) {
        throw new Error("upsertUserFromGithub: row disappeared after insert");
      }
      return row;
    });
    return mapUser(tx());
  }

  getUserById(id: number): User | null {
    const row = this.stmts.getUserById.get(id) as UserRow | undefined;
    return row === undefined ? null : mapUser(row);
  }

  getDaemon(uuid: string): DaemonRow | null {
    const row = this.stmts.getDaemon.get(uuid) as DaemonSqlRow | undefined;
    return row === undefined ? null : mapDaemon(row);
  }

  claimDaemon(uuid: string, userId: number, label?: string): void {
    const now = Math.floor(Date.now() / 1000);
    this.stmts.claimDaemon.run(uuid, userId, label ?? null, now, now);
  }

  countActiveDaemonsForUser(userId: number, uuids: Iterable<string>): number {
    const active = new Set(uuids);
    if (active.size === 0) return 0;
    const owned = this.stmts.listDaemonUuidsForUser.all(userId) as DaemonUuidOnlyRow[];
    let n = 0;
    for (const row of owned) {
      if (active.has(row.uuid)) n++;
    }
    return n;
  }

  getPlan(userId: number): Plan {
    const row = this.stmts.getPlan.get(userId) as PlanRow | undefined;
    if (row !== undefined) return mapPlan(row);
    const defaults = PLAN_DEFAULTS.free;
    return {
      userId,
      tier: "free",
      hookQuotaMonthly: defaults.hookQuotaMonthly,
      concurrentDaemons: defaults.concurrentDaemons,
      oauthProviders: defaults.oauthProviders,
      stripeSubId: null,
      renewsAt: null,
    };
  }

  setPlan(userId: number, tier: Tier): void {
    const d = PLAN_DEFAULTS[tier];
    this.stmts.upsertPlan.run(
      userId,
      tier,
      d.hookQuotaMonthly,
      d.concurrentDaemons,
      serializeOauthProviders(d.oauthProviders),
      null,
      null,
    );
  }

  incrementHookUsage(userId: number, period: string): number {
    const tx = this.handle.transaction(() => {
      this.stmts.incrementHookUsage.run(userId, period);
      const row = this.stmts.getHookUsage.get(userId, period) as HookUsageRow | undefined;
      if (row === undefined) {
        throw new Error("incrementHookUsage: row disappeared after upsert");
      }
      return row.count;
    });
    return tx();
  }

  close(): void {
    this.handle.close();
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export interface OpenDbOptions {
  /** Explicit path. Overrides `DICODE_RELAY_DB` and the default. */
  path?: string;
}

/**
 * Open (or create) the relay database. Creates the parent directory if it
 * does not exist, enables WAL and foreign keys, then runs pending migrations.
 */
export function openDb(options: OpenDbOptions = {}): Db {
  const path = resolveDbPath(options.path);
  mkdirSync(dirname(path), { recursive: true });

  const handle = new Database(path);
  handle.pragma("journal_mode = WAL");
  handle.pragma("foreign_keys = ON");

  // Sanity-check that foreign keys really are on (the pragma is silently
  // ignored inside a transaction, so we verify once at open time).
  const fk = handle.pragma("foreign_keys") as PragmaForeignKeysRow[];
  if (fk[0]?.foreign_keys !== 1) {
    throw new Error("failed to enable SQLite foreign_keys pragma");
  }

  runMigrations(handle);

  return new SqliteDb(handle);
}
