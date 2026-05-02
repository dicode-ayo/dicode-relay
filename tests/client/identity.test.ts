import { createPublicKey, createVerify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Identity } from "../../src/client/identity.js";
import { MemoryKv } from "../../src/client/kv-adapter.js";
import { buildSignedPayload, verifyECDSA } from "../../src/shared/crypto.js";

describe("Identity", () => {
  it("generates and persists a P-256 keypair on first load", async () => {
    const kv = new MemoryKv();
    const id = await Identity.loadOrGenerate(kv);
    expect(id.uuid).toMatch(/^[0-9a-f]{64}$/);
    expect(id.signPubkeyB64).toBeTruthy();
    expect(id.decryptPubkeyB64).toBeTruthy();
  });

  it("returns the same identity on second load", async () => {
    const kv = new MemoryKv();
    const a = await Identity.loadOrGenerate(kv);
    const b = await Identity.loadOrGenerate(kv);
    expect(b.uuid).toBe(a.uuid);
    expect(b.signPubkeyB64).toBe(a.signPubkeyB64);
  });

  it("derives uuid as hex(sha256(uncompressed sign pubkey))", async () => {
    const kv = new MemoryKv();
    const id = await Identity.loadOrGenerate(kv);
    const pkBytes = Uint8Array.from(Buffer.from(id.signPubkeyB64, "base64"));
    expect(pkBytes.length).toBe(65);
    expect(pkBytes[0]).toBe(0x04);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", pkBytes));
    const hex = [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(id.uuid).toBe(hex);
  });

  it("signs a challenge in DER format that round-trips Web Crypto verify", async () => {
    const kv = new MemoryKv();
    const id = await Identity.loadOrGenerate(kv);
    const nonce = "00".repeat(32);
    const ts = 1_700_000_000;
    const sigDerB64 = await id.signChallenge(nonce, ts);
    expect(await id.verifyOwnSignature(nonce, ts, sigDerB64)).toBe(true);
  });

  it("signature verifies via Node's createVerify (broker compatibility)", async () => {
    const kv = new MemoryKv();
    const id = await Identity.loadOrGenerate(kv);
    const nonce = "11".repeat(32);
    const ts = 1_700_000_000;
    const sigDerB64 = await id.signChallenge(nonce, ts);

    // Reconstruct the same message bytes the broker hashes.
    const nonceBytes = Buffer.from(nonce, "hex");
    const tsBuf = Buffer.alloc(8);
    tsBuf.writeBigUInt64BE(BigInt(ts));
    const msg = Buffer.concat([nonceBytes, tsBuf]);

    // Use the raw uncompressed public key wrapped in SPKI DER to verify via Node's createVerify.
    const rawPub = Buffer.from(id.signPubkeyB64, "base64");
    const spkiPrefix = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
    const spki = Buffer.concat([spkiPrefix, rawPub]);

    const pubKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    const sigDerBuf = Buffer.from(sigDerB64, "base64");
    const verify = createVerify("SHA256");
    verify.update(msg);
    // sigDerBuf is already raw DER bytes; pass without encoding argument.
    const ok = verify.verify(pubKey, sigDerBuf);
    expect(ok).toBe(true);
  });

  it("signAuthPayload signature verifies via Node's verifyECDSA (broker compat)", async () => {
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const challenge = "abc123_-";
    const provider = "github";
    const ts = 1_700_000_000;

    const sigDerB64 = await id.signAuthPayload(sessionId, challenge, provider, ts);

    // Broker side: rebuild the signed payload, then call verifyECDSA.
    const payload = buildSignedPayload(sessionId, challenge, id.uuid, provider, ts);
    const pubBytes = Buffer.from(id.signPubkeyB64, "base64");
    expect(verifyECDSA(pubBytes, payload, sigDerB64)).toBe(true);
  });
});
