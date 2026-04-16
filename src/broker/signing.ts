/**
 * Broker signing key — proves delivery envelopes were assembled by this
 * relay instance, not by a forger who knows the daemon's public key.
 *
 * Key resolution order:
 *   1. BROKER_SIGNING_KEY_FILE env → read PEM from file
 *   2. BROKER_SIGNING_KEY env → inline PEM string
 *   3. Auto-generate to <cwd>/broker-signing-key.pem on first start
 *
 * The key is ECDSA P-256 (same curve family as the daemon identity, but a
 * completely separate keypair). Only the relay holds the private half; the
 * public half is announced to every connecting daemon in the WSS welcome
 * message so they can verify delivery signatures.
 */

import { createSign, createVerify, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const AUTO_KEY_FILENAME = "broker-signing-key.pem";

export interface BrokerSigningKey {
  /** Sign sha256(data) with the broker's private key → base64 DER sig */
  sign: (data: Buffer) => string;
  /** Base64-encoded SPKI DER public key (for the welcome message) */
  publicKeyBase64: string;
}

/**
 * Load or generate the broker's signing key.
 *
 * @param env  process.env (or test override)
 * @param cwd  working directory for auto-generated key fallback
 */
export function loadBrokerSigningKey(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): BrokerSigningKey {
  let pem: string;

  if (env.BROKER_SIGNING_KEY_FILE) {
    pem = readFileSync(env.BROKER_SIGNING_KEY_FILE, "utf8");
  } else if (env.BROKER_SIGNING_KEY) {
    pem = env.BROKER_SIGNING_KEY;
  } else {
    const autoPath = join(cwd, AUTO_KEY_FILENAME);
    if (existsSync(autoPath)) {
      pem = readFileSync(autoPath, "utf8");
    } else {
      const pair = generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      writeFileSync(autoPath, pair.privateKey, { mode: 0o600 });
      console.log(
        `broker: generated signing key at ${autoPath} — set BROKER_SIGNING_KEY_FILE to use a persistent key`,
      );
      pem = pair.privateKey;
    }
  }

  // Derive the public key from the private PEM.
  const { publicKey, privateKey } = loadKeyPair(pem);

  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyBase64 = publicKeyDer.toString("base64");

  return {
    sign(data: Buffer): string {
      const signer = createSign("SHA256");
      signer.update(data);
      return signer.sign(privateKey, "base64");
    },
    publicKeyBase64,
  };
}

function loadKeyPair(pem: string) {
  const { createPrivateKey, createPublicKey } = require("node:crypto") as typeof import("node:crypto");
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Build the byte sequence that the broker signs over a delivery envelope.
 * The daemon must reconstruct this exact sequence for verification.
 *
 *   sha256(type || session_id || ephemeral_pubkey || ciphertext || nonce)
 *
 * All fields are UTF-8 encoded (they're already base64/ASCII strings in
 * the envelope JSON). This is deliberately simple: the input is the
 * concatenation of the five immutable envelope fields in wire order.
 */
export function buildDeliverySignaturePayload(
  type: string,
  sessionId: string,
  ephemeralPubkey: string,
  ciphertext: string,
  nonce: string,
): Buffer {
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha256")
    .update(type)
    .update(sessionId)
    .update(ephemeralPubkey)
    .update(ciphertext)
    .update(nonce)
    .digest();
}

/**
 * Verify a delivery envelope signature (used in tests and potentially
 * by daemons implemented in TypeScript).
 */
export function verifyDeliverySignature(
  publicKeyBase64: string,
  sig: string,
  type: string,
  sessionId: string,
  ephemeralPubkey: string,
  ciphertext: string,
  nonce: string,
): boolean {
  const pubKeyDer = Buffer.from(publicKeyBase64, "base64");
  const payload = buildDeliverySignaturePayload(type, sessionId, ephemeralPubkey, ciphertext, nonce);
  const verifier = createVerify("SHA256");
  verifier.update(payload);
  return verifier.verify({ key: pubKeyDer, format: "der", type: "spki" }, Buffer.from(sig, "base64"));
}
