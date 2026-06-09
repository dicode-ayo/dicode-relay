import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Identity } from "../../src/client/identity.js";
import { eciesEncrypt, eciesDecryptWebCrypto } from "../../src/shared/crypto.js";
import {
  buildDeliverySignaturePayload,
  loadBrokerSigningKey,
  verifyDeliverySignature,
} from "../../src/shared/signing.js";

describe("ECIES round-trip with Web Crypto identity", () => {
  it("decrypts an envelope produced by the broker's eciesEncrypt", async () => {
    const id = await Identity.generate();
    const sessionId = "550e8400-e29b-41d4-a716-446655440000";
    const plaintext = Buffer.from(JSON.stringify({ access_token: "secret-abc" }));

    const env = await eciesEncrypt(
      Buffer.from(id.decryptPubkeyB64, "base64"),
      sessionId,
      "oauth_token_delivery",
      plaintext,
    );

    const decrypted = await eciesDecryptWebCrypto(
      id.decryptPrivateKey(),
      sessionId,
      "oauth_token_delivery",
      env,
    );
    expect(JSON.parse(new TextDecoder().decode(decrypted))).toEqual({
      access_token: "secret-abc",
    });
  });

  it("rejects when sessionId differs (HKDF salt mismatch)", async () => {
    const id = await Identity.generate();
    const env = await eciesEncrypt(
      Buffer.from(id.decryptPubkeyB64, "base64"),
      "good-session",
      "oauth_token_delivery",
      Buffer.from("hi"),
    );
    await expect(
      eciesDecryptWebCrypto(id.decryptPrivateKey(), "wrong-session", "oauth_token_delivery", env),
    ).rejects.toThrow();
  });

  it("rejects when messageType differs (AAD mismatch)", async () => {
    const id = await Identity.generate();
    const env = await eciesEncrypt(
      Buffer.from(id.decryptPubkeyB64, "base64"),
      "session",
      "oauth_token_delivery",
      Buffer.from("hi"),
    );
    // Cast to satisfy the EciesMessageType union — uses a wrong label that
    // won't match the AAD bound during encrypt.
    await expect(
      eciesDecryptWebCrypto(id.decryptPrivateKey(), "session", "wrong_type" as never, env),
    ).rejects.toThrow();
  });
});

describe("verifyDeliverySignature integration", () => {
  it("accepts a real broker-signed envelope", () => {
    const tmp = mkdtempSync(join(tmpdir(), "broker-sig-"));
    const broker = loadBrokerSigningKey({}, tmp); // generates fresh key
    const env = {
      type: "oauth_token_delivery" as const,
      session_id: "abcd",
      ephemeral_pubkey: "EPHKEY",
      ciphertext: "CT",
      nonce: "N",
    };
    const payload = buildDeliverySignaturePayload(
      env.type,
      env.session_id,
      env.ephemeral_pubkey,
      env.ciphertext,
      env.nonce,
    );
    const sig = broker.sign(payload);
    expect(
      verifyDeliverySignature(
        broker.publicKeyBase64,
        sig,
        env.type,
        env.session_id,
        env.ephemeral_pubkey,
        env.ciphertext,
        env.nonce,
      ),
    ).toBe(true);
  });

  it("rejects a tampered envelope", () => {
    const tmp = mkdtempSync(join(tmpdir(), "broker-sig-"));
    const broker = loadBrokerSigningKey({}, tmp);
    const payload = buildDeliverySignaturePayload(
      "oauth_token_delivery",
      "abcd",
      "EPHKEY",
      "CT",
      "N",
    );
    const sig = broker.sign(payload);
    expect(
      verifyDeliverySignature(
        broker.publicKeyBase64,
        sig,
        "oauth_token_delivery",
        "abcd",
        "EPHKEY",
        "CT_TAMPERED",
        "N", // ciphertext changed
      ),
    ).toBe(false);
  });
});
