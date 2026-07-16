import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Identity } from "../../src/client/identity.js";
import { buildSignedPayload, verifyECDSA } from "../../src/shared/crypto.js";
import { extractP256PointFromCert, uuidFromP256Point } from "../../src/shared/certs.js";

describe("Identity", () => {
  it("generates a P-256 keypair with valid uuid/pubkeys", async () => {
    const id = await Identity.generate();
    expect(id.uuid).toMatch(/^[0-9a-f]{64}$/);
    expect(id.signPubkeyB64).toBeTruthy();
    expect(id.decryptPubkeyB64).toBeTruthy();
  });

  it("round-trips export → import preserving uuid and pubkeys", async () => {
    const a = await Identity.generate();
    const stored = await a.export();
    const b = await Identity.import(stored);
    expect(b.uuid).toBe(a.uuid);
    expect(b.signPubkeyB64).toBe(a.signPubkeyB64);
    expect(b.decryptPubkeyB64).toBe(a.decryptPubkeyB64);
  });

  it("derives uuid as hex(sha256(uncompressed sign pubkey))", async () => {
    const id = await Identity.generate();
    const pkBytes = Uint8Array.from(Buffer.from(id.signPubkeyB64, "base64"));
    expect(pkBytes.length).toBe(65);
    expect(pkBytes[0]).toBe(0x04);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", pkBytes));
    const hex = [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(id.uuid).toBe(hex);
  });

  it("mintClientCert wraps the sign key: cert SPKI point == signPubkeyB64", async () => {
    const id = await Identity.generate();
    const minted = await id.mintClientCert();

    const cert = new X509Certificate(minted.certPem);
    const point = extractP256PointFromCert(cert);
    if (point === null) throw new Error("cert key is not P-256");
    expect(point.toString("base64")).toBe(id.signPubkeyB64);
    // The broker derives the uuid from this point — must match Identity.uuid.
    expect(uuidFromP256Point(point)).toBe(id.uuid);
  });

  it("mintClientCert produces a fresh certificate each call over the same key", async () => {
    const id = await Identity.generate();
    const first = await id.mintClientCert();
    const second = await id.mintClientCert();

    // Different certificates (random serial) …
    expect(second.certPem).not.toBe(first.certPem);
    const a = new X509Certificate(first.certPem);
    const b = new X509Certificate(second.certPem);
    expect(a.serialNumber).not.toBe(b.serialNumber);

    // … but always the same underlying identity key.
    const pointA = extractP256PointFromCert(a);
    const pointB = extractP256PointFromCert(b);
    if (pointA === null || pointB === null) throw new Error("cert key is not P-256");
    expect(pointA.equals(pointB)).toBe(true);
  });

  it("signAuthPayload signature verifies via Node's verifyECDSA (broker compat)", async () => {
    const id = await Identity.generate();
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
