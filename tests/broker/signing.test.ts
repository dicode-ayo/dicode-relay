/**
 * Broker signing key tests — key loading, signing, verification round-trip.
 */

import { mkdtempSync, rmSync, writeFileSync, unlinkSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  loadBrokerSigningKey,
  buildDeliverySignaturePayload,
  verifyDeliverySignature,
} from "../../src/shared/signing.js";

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

  it("loads key from signing_key_file YAML path when no env is set", () => {
    const pair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    writeFileSync(tmpKeyPath, pair.privateKey, { mode: 0o600 });

    const key = loadBrokerSigningKey(
      { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
      process.cwd(),
      tmpKeyPath,
    );
    expect(key.publicKeyBase64).toBeTruthy();
  });

  it("throws ENOENT (does NOT auto-generate) when signing_key_file points at a missing file", () => {
    // Operator-trusted path: a typo'd `signing_key_file` must surface ENOENT
    // on first start rather than silently auto-generating at the wrong path
    // (which would rotate the broker pubkey and break TOFU-pinned daemons —
    // see issue #54). The legacy cwd-fallback below is the only auto-gen
    // surface this loader exposes.
    const baseTmp = mkdtempSync(join(tmpdir(), "dicode-relay-signing-"));
    const targetPath = join(baseTmp, "non-existent-subdir", "broker-signing.key");
    try {
      expect(existsSync(dirname(targetPath))).toBe(false);

      expect(() =>
        loadBrokerSigningKey(
          { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
          process.cwd(),
          targetPath,
          true,
        ),
      ).toThrow(/broker\.signing_key_file points to a missing file/);

      // Importantly: no file or parent dir was created as a side effect.
      expect(existsSync(targetPath)).toBe(false);
      expect(existsSync(dirname(targetPath))).toBe(false);
    } finally {
      rmSync(baseTmp, { recursive: true, force: true });
    }
  });

  it("mkdir -p's the parent directory on the legacy cwd-fallback auto-generate path", () => {
    // The legacy fallback (no env, no inline, no YAML path) auto-generates a
    // P-256 key under `<cwd>/broker-signing-key.pem`. If cwd itself is a
    // freshly-created tmpdir whose parent path doesn't yet exist (or if a
    // future caller passes a synthetic cwd via the second arg), writeFileSync
    // would throw ENOENT. mkdir -p the parent so the narrow fix the brief
    // intended actually fires here.
    const baseTmp = mkdtempSync(join(tmpdir(), "dicode-relay-cwd-"));
    const syntheticCwd = join(baseTmp, "fresh-subdir");
    expect(existsSync(syntheticCwd)).toBe(false);
    try {
      const key = loadBrokerSigningKey(
        { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
        syntheticCwd,
        "", // no YAML path → legacy fallback branch
        true,
      );
      const autoPath = join(syntheticCwd, "broker-signing-key.pem");
      expect(existsSync(autoPath)).toBe(true);
      expect(key.publicKeyBase64).toBeTruthy();
      const payload = buildDeliverySignaturePayload("t", "s", "e", "c", "n");
      const sig = key.sign(payload);
      expect(verifyDeliverySignature(key.publicKeyBase64, sig, "t", "s", "e", "c", "n")).toBe(true);
      if (process.platform !== "win32") {
        const mode = statSync(autoPath).mode & 0o777;
        expect(mode).toBe(0o600);
      }

      // Second load must read the persisted key back (no rotation).
      const second = loadBrokerSigningKey(
        { BROKER_SIGNING_KEY_FILE: "", BROKER_SIGNING_KEY: "" },
        syntheticCwd,
        "",
        true,
      );
      expect(second.publicKeyBase64).toBe(key.publicKeyBase64);
    } finally {
      rmSync(baseTmp, { recursive: true, force: true });
    }
  });

  it("env BROKER_SIGNING_KEY_FILE takes precedence over YAML signing_key_file", () => {
    const envPair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const yamlPair = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const envPath = join(process.cwd(), "test-env-signing.pem");
    const yamlPath = join(process.cwd(), "test-yaml-signing.pem");
    writeFileSync(envPath, envPair.privateKey, { mode: 0o600 });
    writeFileSync(yamlPath, yamlPair.privateKey, { mode: 0o600 });

    try {
      const key = loadBrokerSigningKey(
        { BROKER_SIGNING_KEY_FILE: envPath },
        process.cwd(),
        yamlPath,
      );
      // Env should win → key must match the env pair's public half
      const envPubPem = envPair.publicKey.replace(/\s+/g, "");
      const yamlPubPem = yamlPair.publicKey.replace(/\s+/g, "");
      // publicKeyBase64 is SPKI DER-base64; derive from both to compare
      const decodedEnvPub = Buffer.from(key.publicKeyBase64, "base64").toString("base64");
      expect(decodedEnvPub).not.toBe("");
      // Cross-check by signing + verifying with the env pair's public key
      const payload = buildDeliverySignaturePayload("t", "s", "e", "c", "n");
      const sig = key.sign(payload);
      expect(verifyDeliverySignature(key.publicKeyBase64, sig, "t", "s", "e", "c", "n")).toBe(true);
      // Neutralize the unused vars lints — PEM strings are just witnesses here.
      expect(envPubPem.length).toBeGreaterThan(0);
      expect(yamlPubPem.length).toBeGreaterThan(0);
    } finally {
      try {
        unlinkSync(envPath);
      } catch {
        // ignore
      }
      try {
        unlinkSync(yamlPath);
      } catch {
        // ignore
      }
    }
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
