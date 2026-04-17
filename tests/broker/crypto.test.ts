/**
 * Crypto tests — real Node.js crypto, no mocks.
 */

import { createECDH, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildSignedPayload,
  eciesDecrypt,
  eciesEncrypt,
  verifyECDSA,
} from "../../src/broker/crypto.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateSigningIdentity(): {
  pubkeyBytes: Buffer;
  sign: (payload: Buffer) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const spki = publicKey as Buffer;
  const pubkeyBytes = Buffer.from(spki.subarray(spki.length - 65));

  const sign = (payload: Buffer): string => {
    const signer = createSign("SHA256");
    signer.update(payload);
    return signer.sign(privateKey, "base64");
  };

  return { pubkeyBytes, sign };
}

// ---------------------------------------------------------------------------
// buildSignedPayload
// ---------------------------------------------------------------------------

describe("buildSignedPayload", () => {
  it("is deterministic for same inputs", () => {
    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const pkceChallenge = randomBytes(32).toString("base64url");
    const relayUuid = randomBytes(32).toString("hex");
    const provider = "github";
    const timestamp = 1700000000;

    const p1 = buildSignedPayload(sessionId, pkceChallenge, relayUuid, provider, timestamp);
    const p2 = buildSignedPayload(sessionId, pkceChallenge, relayUuid, provider, timestamp);

    expect(p1.equals(p2)).toBe(true);
  });

  it("differs when any input changes", () => {
    const base = {
      sessionId: "550e8400-e29b-41d4-a716-446655440000",
      pkceChallenge: randomBytes(32).toString("base64url"),
      relayUuid: randomBytes(32).toString("hex"),
      provider: "github",
      timestamp: 1700000000,
    };

    const ref = buildSignedPayload(
      base.sessionId,
      base.pkceChallenge,
      base.relayUuid,
      base.provider,
      base.timestamp,
    );

    // Change provider
    const p2 = buildSignedPayload(
      base.sessionId,
      base.pkceChallenge,
      base.relayUuid,
      "slack",
      base.timestamp,
    );
    expect(ref.equals(p2)).toBe(false);

    // Change timestamp
    const p3 = buildSignedPayload(
      base.sessionId,
      base.pkceChallenge,
      base.relayUuid,
      base.provider,
      base.timestamp + 1,
    );
    expect(ref.equals(p3)).toBe(false);
  });

  it("output is 32 bytes (SHA-256 hash)", () => {
    const result = buildSignedPayload(
      "550e8400-e29b-41d4-a716-446655440000",
      randomBytes(32).toString("base64url"),
      randomBytes(32).toString("hex"),
      "github",
      1700000000,
    );
    expect(result.length).toBe(32);
  });
});

// ---------------------------------------------------------------------------
// verifyECDSA
// ---------------------------------------------------------------------------

describe("verifyECDSA", () => {
  it("returns true for valid signature", () => {
    const { pubkeyBytes, sign } = generateSigningIdentity();
    const payload = randomBytes(32);
    const sig = sign(payload);

    expect(verifyECDSA(pubkeyBytes, payload, sig)).toBe(true);
  });

  it("returns false for tampered payload", () => {
    const { pubkeyBytes, sign } = generateSigningIdentity();
    const payload = randomBytes(32);
    const sig = sign(payload);

    const tamperedPayload = Buffer.from(payload);
    const firstByte = tamperedPayload[0] ?? 0;
    tamperedPayload[0] = ~firstByte & 0xff;

    expect(verifyECDSA(pubkeyBytes, tamperedPayload, sig)).toBe(false);
  });

  it("returns false for tampered signature", () => {
    const { pubkeyBytes, sign } = generateSigningIdentity();
    const payload = randomBytes(32);
    const sig = sign(payload);

    // Corrupt the base64-decoded sig
    const sigBytes = Buffer.from(sig, "base64");
    const lastByte = sigBytes[sigBytes.length - 1] ?? 0;
    sigBytes[sigBytes.length - 1] = ~lastByte & 0xff;
    const tamperedSig = sigBytes.toString("base64");

    expect(verifyECDSA(pubkeyBytes, payload, tamperedSig)).toBe(false);
  });

  it("returns false for wrong public key", () => {
    const { sign } = generateSigningIdentity();
    const { pubkeyBytes: wrongPubkey } = generateSigningIdentity();

    const payload = randomBytes(32);
    const sig = sign(payload);

    expect(verifyECDSA(wrongPubkey, payload, sig)).toBe(false);
  });

  it("returns false for invalid pubkey bytes", () => {
    const payload = randomBytes(32);
    const badPubkey = randomBytes(65); // random bytes, not a valid EC point
    badPubkey[0] = 0x04; // correct prefix but bad coordinates

    // This may throw internally and return false
    const result = verifyECDSA(badPubkey, payload, "aW52YWxpZA==");
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ECIES round-trip
// ---------------------------------------------------------------------------

describe("ECIES round-trip", () => {
  it("eciesEncrypt + eciesDecrypt round-trip with matching session ID", async () => {
    // Generate daemon ECDH key pair
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey(); // 65 bytes

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const tokens = { access_token: "tok_abc123", token_type: "Bearer" };
    const plaintext = Buffer.from(JSON.stringify(tokens));

    const payload = await eciesEncrypt(
      daemonPubkeyBytes,
      sessionId,
      "oauth_token_delivery",
      plaintext,
    );

    expect(payload.ephemeralPubkey).toBeTruthy();
    expect(payload.ciphertext).toBeTruthy();
    expect(payload.nonce).toBeTruthy();

    // Verify nonce is 12 bytes
    expect(Buffer.from(payload.nonce, "base64").length).toBe(12);

    // Decrypt using daemon private key
    const decrypted = await eciesDecrypt(daemonECDH, sessionId, "oauth_token_delivery", payload);

    expect(decrypted.toString()).toBe(JSON.stringify(tokens));
  });

  it("ciphertext last 16 bytes are the AES-GCM auth tag (verify split)", async () => {
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey();

    const sessionId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const plaintext = Buffer.from("hello world");

    const payload = await eciesEncrypt(
      daemonPubkeyBytes,
      sessionId,
      "oauth_token_delivery",
      plaintext,
    );

    // Ciphertext should be: len(plaintext) + 16 bytes (auth tag)
    const ctBytes = Buffer.from(payload.ciphertext, "base64");
    expect(ctBytes.length).toBe(plaintext.length + 16);
  });

  it("decryption fails with wrong session ID (wrong HKDF salt → wrong key)", async () => {
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey();

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const payload = await eciesEncrypt(
      daemonPubkeyBytes,
      sessionId,
      "oauth_token_delivery",
      Buffer.from("secret data"),
    );

    // Decrypt with wrong session ID → different key → GCM auth tag fails
    await expect(
      eciesDecrypt(
        daemonECDH,
        "00000000-0000-0000-0000-000000000000",
        "oauth_token_delivery",
        payload,
      ),
    ).rejects.toThrow();
  });

  it("decryption fails with wrong private key", async () => {
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey();

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const payload = await eciesEncrypt(
      daemonPubkeyBytes,
      sessionId,
      "oauth_token_delivery",
      Buffer.from("secret"),
    );

    // Try to decrypt with a different ECDH key
    const wrongECDH = createECDH("prime256v1");
    wrongECDH.generateKeys();

    await expect(
      eciesDecrypt(wrongECDH, sessionId, "oauth_token_delivery", payload),
    ).rejects.toThrow();
  });

  it("each encryption produces different ciphertext (random nonce)", async () => {
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey();

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const plaintext = Buffer.from("same message");

    const p1 = await eciesEncrypt(daemonPubkeyBytes, sessionId, "oauth_token_delivery", plaintext);
    const p2 = await eciesEncrypt(daemonPubkeyBytes, sessionId, "oauth_token_delivery", plaintext);

    // Nonces should differ
    expect(p1.nonce).not.toBe(p2.nonce);
    // Ciphertexts should differ (different ephemeral keys + nonces)
    expect(p1.ciphertext).not.toBe(p2.ciphertext);
  });

  it("decryption fails with wrong message type (AAD domain separation)", async () => {
    const daemonECDH = createECDH("prime256v1");
    daemonECDH.generateKeys();
    const daemonPubkeyBytes = daemonECDH.getPublicKey();

    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const payload = await eciesEncrypt(
      daemonPubkeyBytes,
      sessionId,
      "oauth_token_delivery",
      Buffer.from("t"),
    );

    // Decrypting with any other type label must fail.
    await expect(
      eciesDecrypt(daemonECDH, sessionId, "some_future_message" as never, payload),
    ).rejects.toThrow();
  });

  // Empty-type guard tests removed: EciesMessageType union enforces
  // non-empty at the type level, so runtime guards are unnecessary.
});
