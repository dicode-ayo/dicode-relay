import { describe, expect, it } from "vitest";
import { TofuStore } from "../../src/client/tofu.js";
import { MemoryKv } from "../../src/client/kv-adapter.js";

describe("TofuStore", () => {
  it("returns 'new' on first pubkey", async () => {
    const t = new TofuStore(new MemoryKv());
    expect(await t.checkAndPin("PUBKEY_A")).toBe("new");
  });
  it("returns 'match' on second pin of same key", async () => {
    const kv = new MemoryKv();
    const t = new TofuStore(kv);
    await t.checkAndPin("PUBKEY_A");
    expect(await t.checkAndPin("PUBKEY_A")).toBe("match");
  });
  it("returns 'mismatch' if pubkey changed", async () => {
    const kv = new MemoryKv();
    const t = new TofuStore(kv);
    await t.checkAndPin("PUBKEY_A");
    expect(await t.checkAndPin("PUBKEY_B")).toBe("mismatch");
  });
});
