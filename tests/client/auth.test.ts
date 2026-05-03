import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Identity } from "../../src/client/identity.js";
import { buildAuthURL, decryptTokenEnvelope } from "../../src/client/auth.js";
import { eciesEncrypt, buildSignedPayload, verifyECDSA } from "../../src/shared/crypto.js";
import { loadBrokerSigningKey, buildDeliverySignaturePayload } from "../../src/shared/signing.js";
import type { OAuthTokenDeliveryPayload } from "../../src/shared/protocol.js";

describe("buildAuthURL", () => {
  it("produces a URL whose signature verifies against the daemon pubkey", async () => {
    const id = await Identity.generate();
    const result = await buildAuthURL({
      provider: "github",
      scope: "repo",
      identity: id,
      brokerURL: "https://relay.example",
      challenge: "test_challenge",
    });

    const u = new URL(result.url);
    expect(u.pathname).toBe("/auth/github");
    expect(u.searchParams.get("relay_uuid")).toBe(id.uuid);
    expect(u.searchParams.get("scope")).toBe("repo");

    const sessionId = u.searchParams.get("session_id") ?? "";
    const ts = Number(u.searchParams.get("ts"));
    const sig = u.searchParams.get("sig") ?? "";
    const challenge = u.searchParams.get("challenge") ?? "";

    const payload = buildSignedPayload(sessionId, challenge, id.uuid, "github", ts);
    const pubBytes = Buffer.from(id.signPubkeyB64, "base64");
    expect(verifyECDSA(pubBytes, payload, sig)).toBe(true);
  });

  it("omits scope param when not supplied", async () => {
    const id = await Identity.generate();
    const result = await buildAuthURL({
      provider: "slack",
      identity: id,
      brokerURL: "https://relay.example",
      challenge: "x",
    });
    const u = new URL(result.url);
    expect(u.searchParams.has("scope")).toBe(false);
  });
});

describe("decryptTokenEnvelope", () => {
  it("verifies broker_sig and decrypts the plaintext token map", async () => {
    const id = await Identity.generate();
    const tmp = mkdtempSync(join(tmpdir(), "broker-key-"));
    const broker = loadBrokerSigningKey({}, tmp);

    const sessionId = "abcd-1234";
    const tokenJson = JSON.stringify({ access_token: "abc-123", scope: "repo" });

    const eciesPayload = await eciesEncrypt(
      Buffer.from(id.decryptPubkeyB64, "base64"),
      sessionId,
      "oauth_token_delivery",
      Buffer.from(tokenJson),
    );

    // Broker assembles the envelope and signs it.
    const sigPayload = buildDeliverySignaturePayload(
      "oauth_token_delivery",
      sessionId,
      eciesPayload.ephemeralPubkey,
      eciesPayload.ciphertext,
      eciesPayload.nonce,
    );
    const brokerSig = broker.sign(sigPayload);

    const env: OAuthTokenDeliveryPayload = {
      type: "oauth_token_delivery",
      session_id: sessionId,
      ephemeral_pubkey: eciesPayload.ephemeralPubkey,
      ciphertext: eciesPayload.ciphertext,
      nonce: eciesPayload.nonce,
      broker_sig: brokerSig,
    };

    const tokens = await decryptTokenEnvelope(env, id, broker.publicKeyBase64);
    expect(tokens.access_token).toBe("abc-123");
    expect(tokens.scope).toBe("repo");
  });

  it("rejects when broker_sig is missing", async () => {
    const id = await Identity.generate();
    const env: OAuthTokenDeliveryPayload = {
      type: "oauth_token_delivery",
      session_id: "x",
      ephemeral_pubkey: "",
      ciphertext: "",
      nonce: "",
    };
    await expect(decryptTokenEnvelope(env, id, "BROKER_PK")).rejects.toThrow(/missing broker_sig/);
  });

  it("rejects when broker_sig is invalid", async () => {
    const id = await Identity.generate();
    const tmp = mkdtempSync(join(tmpdir(), "broker-key-"));
    const broker = loadBrokerSigningKey({}, tmp);

    const env: OAuthTokenDeliveryPayload = {
      type: "oauth_token_delivery",
      session_id: "x",
      ephemeral_pubkey: "AAAA",
      ciphertext: "BBBB",
      nonce: "CCCC",
      broker_sig: "INVALID",
    };
    await expect(decryptTokenEnvelope(env, id, broker.publicKeyBase64)).rejects.toThrow(
      /broker signature/,
    );
  });
});
