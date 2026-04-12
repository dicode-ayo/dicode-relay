import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

import { openDb, type Db, DaemonAlreadyClaimedError } from "../../src/db/index.js";

interface Ctx {
  dir: string;
  dbPath: string;
  db: Db;
}

const ctx: Ctx = {
  dir: "",
  dbPath: "",
  db: null as unknown as Db,
};

beforeEach(() => {
  ctx.dir = mkdtempSync(join(tmpdir(), "relay-db-"));
  ctx.dbPath = join(ctx.dir, "relay.db");
  ctx.db = openDb({ path: ctx.dbPath });
});

afterEach(() => {
  ctx.db.close();
  rmSync(ctx.dir, { recursive: true, force: true });
});

describe("openDb", () => {
  it("creates the database file on first open", () => {
    expect(existsSync(ctx.dbPath)).toBe(true);
  });

  it("creates the parent directory if it does not exist", () => {
    ctx.db.close();
    const nestedDir = join(ctx.dir, "nested", "sub");
    const nestedPath = join(nestedDir, "relay.db");
    const db2 = openDb({ path: nestedPath });
    expect(existsSync(nestedPath)).toBe(true);
    db2.close();
  });

  it("has foreign_keys pragma enabled", () => {
    const raw = new Database(ctx.dbPath);
    const pragma = raw.pragma("foreign_keys") as { foreign_keys: number }[];
    expect(pragma[0]?.foreign_keys).toBe(1);
    raw.close();
    // The real proof is that openDb would have thrown if fk pragma failed;
    // also verify via a raw handle that cascade constraints are registered.
    const raw2 = new Database(ctx.dbPath);
    raw2.pragma("foreign_keys = ON");
    raw2
      .prepare("INSERT INTO users (github_id, github_login, created_at) VALUES (?, ?, ?)")
      .run(1, "alice", 1000);
    raw2
      .prepare("INSERT INTO daemons (uuid, user_id, first_seen, last_seen) VALUES (?, ?, ?, ?)")
      .run("aa", 1, 1, 1);
    raw2.prepare("DELETE FROM users WHERE id = ?").run(1);
    const remaining = raw2.prepare("SELECT COUNT(*) AS n FROM daemons").get() as {
      n: number;
    };
    expect(remaining.n).toBe(0);
    raw2.close();
  });

  it("is idempotent — running migrations twice does not error", () => {
    ctx.db.close();
    const db2 = openDb({ path: ctx.dbPath });
    db2.close();
    const db3 = openDb({ path: ctx.dbPath });
    db3.close();
    // Verify schema_version has exactly one row for version 1.
    const raw = new Database(ctx.dbPath);
    const rows = raw.prepare("SELECT version FROM schema_version ORDER BY version").all() as {
      version: number;
    }[];
    expect(rows.map((r) => r.version)).toEqual([1]);
    raw.close();
    // Re-open for afterEach cleanup.
    ctx.db = openDb({ path: ctx.dbPath });
  });

  it("honours DICODE_RELAY_DB when no explicit path is supplied", () => {
    ctx.db.close();
    const envPath = join(ctx.dir, "env.db");
    const saved = process.env.DICODE_RELAY_DB;
    process.env.DICODE_RELAY_DB = envPath;
    try {
      const db2 = openDb();
      expect(existsSync(envPath)).toBe(true);
      db2.close();
    } finally {
      if (saved === undefined) delete process.env.DICODE_RELAY_DB;
      else process.env.DICODE_RELAY_DB = saved;
    }
    ctx.db = openDb({ path: ctx.dbPath });
  });
});

describe("users", () => {
  it("round-trips upsertUserFromGithub / getUserById", () => {
    const u = ctx.db.upsertUserFromGithub({
      githubId: 42,
      login: "alice",
      email: "alice@example.com",
    });
    expect(u.id).toBeGreaterThan(0);
    expect(u.githubId).toBe(42);
    expect(u.githubLogin).toBe("alice");
    expect(u.email).toBe("alice@example.com");
    expect(u.githubAccessTokenEncrypted).toBeNull();
    expect(u.createdAt).toBeGreaterThan(0);

    const fetched = ctx.db.getUserById(u.id);
    expect(fetched).not.toBeNull();
    expect(fetched?.githubId).toBe(42);
  });

  it("upsert updates mutable fields but preserves id", () => {
    const a = ctx.db.upsertUserFromGithub({ githubId: 7, login: "bob" });
    const b = ctx.db.upsertUserFromGithub({
      githubId: 7,
      login: "bob-renamed",
      email: "bob@example.com",
    });
    expect(b.id).toBe(a.id);
    expect(b.githubLogin).toBe("bob-renamed");
    expect(b.email).toBe("bob@example.com");
  });

  it("upsert preserves existing token when new call omits one", () => {
    const token = Buffer.from("sekrit");
    ctx.db.upsertUserFromGithub({ githubId: 9, login: "carol" }, token);
    const after = ctx.db.upsertUserFromGithub({ githubId: 9, login: "carol" });
    expect(after.githubAccessTokenEncrypted?.toString()).toBe("sekrit");
  });

  it("stores and returns a fresh token buffer", () => {
    const token = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const u = ctx.db.upsertUserFromGithub({ githubId: 11, login: "dave" }, token);
    expect(u.githubAccessTokenEncrypted?.equals(token)).toBe(true);
  });

  it("getUserById returns null for unknown id", () => {
    expect(ctx.db.getUserById(999_999)).toBeNull();
  });

  it("accepts null email", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 5, login: "eve", email: null });
    expect(u.email).toBeNull();
  });
});

describe("daemons", () => {
  it("claim + get round-trip", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 1, login: "alice" });
    ctx.db.claimDaemon("a".repeat(64), u.id, "laptop");
    const d = ctx.db.getDaemon("a".repeat(64));
    expect(d).not.toBeNull();
    expect(d?.userId).toBe(u.id);
    expect(d?.label).toBe("laptop");
    expect(d?.firstSeen).toBeGreaterThan(0);
  });

  it("claim without label stores null", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 2, login: "bob" });
    ctx.db.claimDaemon("b".repeat(64), u.id);
    const d = ctx.db.getDaemon("b".repeat(64));
    expect(d?.label).toBeNull();
  });

  it("re-claim updates last_seen and preserves label when omitted", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 3, login: "carol" });
    ctx.db.claimDaemon("c".repeat(64), u.id, "desktop");
    const first = ctx.db.getDaemon("c".repeat(64));
    ctx.db.claimDaemon("c".repeat(64), u.id);
    const second = ctx.db.getDaemon("c".repeat(64));
    expect(second?.label).toBe("desktop");
    expect(second?.lastSeen).toBeGreaterThanOrEqual(first?.lastSeen ?? 0);
  });

  it("getDaemon returns null for unknown uuid", () => {
    expect(ctx.db.getDaemon("x".repeat(64))).toBeNull();
  });

  it("countActiveDaemonsForUser filters by the supplied active set", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 4, login: "dave" });
    ctx.db.claimDaemon("1".repeat(64), u.id);
    ctx.db.claimDaemon("2".repeat(64), u.id);
    ctx.db.claimDaemon("3".repeat(64), u.id);

    expect(ctx.db.countActiveDaemonsForUser(u.id, ["1".repeat(64)])).toBe(1);
    expect(ctx.db.countActiveDaemonsForUser(u.id, ["1".repeat(64), "2".repeat(64)])).toBe(2);
    // Unknown uuids are ignored
    expect(ctx.db.countActiveDaemonsForUser(u.id, ["1".repeat(64), "z".repeat(64)])).toBe(1);
    // Empty active set → 0
    expect(ctx.db.countActiveDaemonsForUser(u.id, [])).toBe(0);
    // Other user's uuids don't count even if active
    const u2 = ctx.db.upsertUserFromGithub({ githubId: 5, login: "eve" });
    expect(ctx.db.countActiveDaemonsForUser(u2.id, ["1".repeat(64)])).toBe(0);
  });
});

describe("plans", () => {
  it("getPlan returns free defaults for unknown user without inserting a row", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 1, login: "alice" });
    const p = ctx.db.getPlan(u.id);
    expect(p.tier).toBe("free");
    expect(p.hookQuotaMonthly).toBe(1_000);
    expect(p.concurrentDaemons).toBe(1);
    expect(p.oauthProviders).toEqual(["github"]);
    expect(p.stripeSubId).toBeNull();
    expect(p.renewsAt).toBeNull();

    // Verify no row was inserted on the read.
    const raw = new Database(ctx.dbPath);
    const count = raw.prepare("SELECT COUNT(*) AS n FROM plans").get() as { n: number };
    expect(count.n).toBe(0);
    raw.close();
  });

  it("setPlan + getPlan round-trips pro tier", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 2, login: "bob" });
    ctx.db.setPlan(u.id, "pro");
    const p = ctx.db.getPlan(u.id);
    expect(p.tier).toBe("pro");
    expect(p.hookQuotaMonthly).toBe(50_000);
    expect(p.concurrentDaemons).toBe(3);
    expect(p.oauthProviders).toBe("*");
  });

  it("setPlan + getPlan round-trips team tier", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 3, login: "carol" });
    ctx.db.setPlan(u.id, "team");
    const p = ctx.db.getPlan(u.id);
    expect(p.tier).toBe("team");
    expect(p.hookQuotaMonthly).toBe(500_000);
    expect(p.concurrentDaemons).toBe(10);
    expect(p.oauthProviders).toBe("*");
  });

  it("setPlan can downgrade back to free", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 4, login: "dave" });
    ctx.db.setPlan(u.id, "pro");
    ctx.db.setPlan(u.id, "free");
    const p = ctx.db.getPlan(u.id);
    expect(p.tier).toBe("free");
    expect(p.oauthProviders).toEqual(["github"]);
  });
});

describe("hook usage", () => {
  it("increments atomically and returns the new count", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 1, login: "alice" });
    expect(ctx.db.incrementHookUsage(u.id, "2026-04")).toBe(1);
    expect(ctx.db.incrementHookUsage(u.id, "2026-04")).toBe(2);
    expect(ctx.db.incrementHookUsage(u.id, "2026-04")).toBe(3);
    // Different period → starts at 1
    expect(ctx.db.incrementHookUsage(u.id, "2026-05")).toBe(1);
  });

  it("is atomic under concurrent Promise.all calls", async () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 2, login: "bob" });
    const N = 200;
    const results = await Promise.all(
      Array.from({ length: N }, () =>
        Promise.resolve().then(() => ctx.db.incrementHookUsage(u.id, "2026-04")),
      ),
    );
    // Each call should return a unique count from 1..N
    const sorted = [...results].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    expect(sorted[sorted.length - 1]).toBe(N);
    expect(new Set(sorted).size).toBe(N);
  });
});

describe("db file permissions", () => {
  it("sets mode 0600 on a freshly created database file", () => {
    if (platform() === "win32") return; // POSIX perms don't apply
    const st = statSync(ctx.dbPath);
    const looseBits = st.mode & 0o077;
    expect(looseBits).toBe(0);
  });

  it("narrows mode to 0600 when opening a loose-permissioned existing file", async () => {
    if (platform() === "win32") return;
    // Close, widen, reopen.
    ctx.db.close();
    const { chmodSync } = await import("node:fs");
    chmodSync(ctx.dbPath, 0o644);
    ctx.db = openDb({ path: ctx.dbPath });
    const st = statSync(ctx.dbPath);
    expect(st.mode & 0o077).toBe(0);
  });
});

describe("upsertUserFromGithub email preservation", () => {
  it("preserves existing email when a subsequent call omits it", () => {
    const a = ctx.db.upsertUserFromGithub({
      githubId: 100,
      login: "alice",
      email: "alice@example.com",
    });
    // Second call without email should NOT wipe the stored one.
    const b = ctx.db.upsertUserFromGithub({ githubId: 100, login: "alice-renamed" });
    expect(b.id).toBe(a.id);
    expect(b.githubLogin).toBe("alice-renamed");
    expect(b.email).toBe("alice@example.com");
  });

  it("overwrites email when a new non-null value is supplied", () => {
    ctx.db.upsertUserFromGithub({
      githubId: 101,
      login: "alice",
      email: "old@example.com",
    });
    const b = ctx.db.upsertUserFromGithub({
      githubId: 101,
      login: "alice",
      email: "new@example.com",
    });
    expect(b.email).toBe("new@example.com");
  });
});

describe("claimDaemonStrict", () => {
  const uuid = "d".repeat(64);

  it("inserts a new row when the uuid is unknown", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 200, login: "alice" });
    ctx.db.claimDaemonStrict(uuid, u.id, "laptop");
    const d = ctx.db.getDaemon(uuid);
    expect(d?.userId).toBe(u.id);
    expect(d?.label).toBe("laptop");
  });

  it("refreshes last_seen on re-claim by the same owner", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 201, login: "alice" });
    ctx.db.claimDaemonStrict(uuid, u.id, "laptop");
    const before = ctx.db.getDaemon(uuid)?.lastSeen ?? 0;
    ctx.db.claimDaemonStrict(uuid, u.id);
    const after = ctx.db.getDaemon(uuid)?.lastSeen ?? 0;
    expect(after).toBeGreaterThanOrEqual(before);
  });

  it("preserves the original label when re-claim omits one", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 202, login: "alice" });
    ctx.db.claimDaemonStrict(uuid, u.id, "laptop");
    ctx.db.claimDaemonStrict(uuid, u.id);
    expect(ctx.db.getDaemon(uuid)?.label).toBe("laptop");
  });

  it("updates the label when re-claim supplies a new one", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 203, login: "alice" });
    ctx.db.claimDaemonStrict(uuid, u.id, "laptop");
    ctx.db.claimDaemonStrict(uuid, u.id, "desktop");
    expect(ctx.db.getDaemon(uuid)?.label).toBe("desktop");
  });

  it("throws DaemonAlreadyClaimedError when a different user tries to claim", () => {
    const a = ctx.db.upsertUserFromGithub({ githubId: 204, login: "alice" });
    const b = ctx.db.upsertUserFromGithub({ githubId: 205, login: "bob" });
    ctx.db.claimDaemonStrict(uuid, a.id, "alice-laptop");

    expect(() => {
      ctx.db.claimDaemonStrict(uuid, b.id, "bob-laptop");
    }).toThrowError(DaemonAlreadyClaimedError);

    // Original binding and label must be untouched.
    const d = ctx.db.getDaemon(uuid);
    expect(d?.userId).toBe(a.id);
    expect(d?.label).toBe("alice-laptop");
  });

  it("DaemonAlreadyClaimedError carries the conflicting uuid and owner", () => {
    const a = ctx.db.upsertUserFromGithub({ githubId: 206, login: "alice" });
    const b = ctx.db.upsertUserFromGithub({ githubId: 207, login: "bob" });
    ctx.db.claimDaemonStrict(uuid, a.id);
    try {
      ctx.db.claimDaemonStrict(uuid, b.id);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(DaemonAlreadyClaimedError);
      const e = err as DaemonAlreadyClaimedError;
      expect(e.uuid).toBe(uuid);
      expect(e.ownerUserId).toBe(a.id);
    }
  });
});

describe("foreign-key cascade", () => {
  it("deleting a user cascades to daemons, plans, and hook_usage", () => {
    const u = ctx.db.upsertUserFromGithub({ githubId: 1, login: "alice" });
    ctx.db.claimDaemon("a".repeat(64), u.id, "laptop");
    ctx.db.setPlan(u.id, "pro");
    ctx.db.incrementHookUsage(u.id, "2026-04");

    const raw = new Database(ctx.dbPath);
    raw.pragma("foreign_keys = ON");
    raw.prepare("DELETE FROM users WHERE id = ?").run(u.id);

    const daemons = raw.prepare("SELECT COUNT(*) AS n FROM daemons").get() as {
      n: number;
    };
    const plans = raw.prepare("SELECT COUNT(*) AS n FROM plans").get() as { n: number };
    const usage = raw.prepare("SELECT COUNT(*) AS n FROM hook_usage").get() as {
      n: number;
    };
    expect(daemons.n).toBe(0);
    expect(plans.n).toBe(0);
    expect(usage.n).toBe(0);
    raw.close();
  });
});
