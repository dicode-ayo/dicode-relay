/**
 * Broker signing key tests — key loading, signing, verification round-trip.
 */

import { writeFileSync, unlinkSync, existsSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadBrokerSigningKey,
  buildDeliverySignaturePayload,
  verifyDeliverySignature,
} from "../../src/broker/signing.js";

const tmpKeyPath = join(process.cwd(), "test-broker-signing-key.pem");

afterEach(() => {
  try {
    unlinkSync(tmpKeyPath);
  } catch {
    // ignore
  }
});

describe("loadBrokerSigningKey", () => {
  it("auto-generates a key file if none exists", () => {
    // Point at a path that doesn't exist yet
    const key = loadBrokerSigningKey(
      { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
      process.cwd(),
    );
    expect(key.publicKeyBase64).toBeTruthy();
    expect(typeof key.sign).toBe("function");

    // Clean up auto-generated file
    const autoPath = join(process.cwd(), "broker-signing-key.pem");
    if (existsSync(autoPath)) unlinkSync(autoPath);
  });

  it("loads key from BROKER_SIGNING_KEY_FILE env", () => {
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    writeFileSync(tmpKeyPath, pair.privateKey, { mode: 0o600 });

    const key = loadBrokerSigningKey({ BROKER_SIGNING_KEY_FILE: tmpKeyPath }, process.cwd());
    expect(key.publicKeyBase64).toBeTruthy();
  });

  it("loads key from inline BROKER_SIGNING_KEY env", () => {
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const key = loadBrokerSigningKey({ BROKER_SIGNING_KEY: pair.privateKey }, process.cwd());
    expect(key.publicKeyBase64).toBeTruthy();
  });
});

describe("sign + verify round-trip", () => {
  it("produces a valid signature that verifyDeliverySignature accepts", () => {
    const key = loadBrokerSigningKey(
      { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
      process.cwd(),
    );

    const type = "oauth_token_delivery";
    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const ephPubkey = "AAAA";
    const ciphertext = "BBBB";
    const nonce = "CCCC";

    const payload = buildDeliverySignaturePayload(type, sessionId, ephPubkey, ciphertext, nonce);
    const sig = key.sign(payload);

    expect(sig).toBeTruthy();

    const valid = verifyDeliverySignature(
      key.publicKeyBase64,
      sig,
      type,
      sessionId,
      ephPubkey,
      ciphertext,
      nonce,
    );
    expect(valid).toBe(true);

    // Clean up auto-generated file
    const autoPath = join(process.cwd(), "broker-signing-key.pem");
    if (existsSync(autoPath)) unlinkSync(autoPath);
  });

  it("rejects tampered ciphertext", () => {
    const key = loadBrokerSigningKey(
      { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
      process.cwd(),
    );

    const payload = buildDeliverySignaturePayload("t", "s", "e", "ct", "n");
    const sig = key.sign(payload);

    const valid = verifyDeliverySignature(key.publicKeyBase64, sig, "t", "s", "e", "TAMPERED", "n");
    expect(valid).toBe(false);

    const autoPath = join(process.cwd(), "broker-signing-key.pem");
    if (existsSync(autoPath)) unlinkSync(autoPath);
  });
});

describe("buildDeliverySignaturePayload", () => {
  it("is deterministic", () => {
    const a = buildDeliverySignaturePayload("t", "s", "e", "c", "n");
    const b = buildDeliverySignaturePayload("t", "s", "e", "c", "n");
    expect(a.equals(b)).toBe(true);
  });

  it("output is 32 bytes (SHA-256)", () => {
    const p = buildDeliverySignaturePayload("t", "s", "e", "c", "n");
    expect(p.length).toBe(32);
  });
});
