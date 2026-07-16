/**
 * Cryptographic primitives for the OAuth broker.
 *
 * - verifyECDSA: verify an ECDSA P-256 signature from the daemon
 * - eciesEncrypt: encrypt a token payload for the daemon using ECIES
 * - buildSignedPayload: construct the exact byte sequence the daemon signs
 *
 * ECIES ciphertext format:
 *   The last 16 bytes of the ciphertext field are the AES-GCM authentication tag.
 *   The Go daemon must split them off before calling aesGCM.Open:
 *     ct  := ciphertextBytes[:len-16]
 *     tag := ciphertextBytes[len-16:]
 */

import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createVerify,
  hkdf,
  randomBytes,
} from "node:crypto";
import type { webcrypto } from "node:crypto";
import { promisify } from "node:util";

const hkdfAsync = promisify(hkdf);

// ---------------------------------------------------------------------------
// ECIES message type — ASCII-only so that Buffer.from(type, "utf8") (TS)
// and []byte(type) (Go) produce identical AAD bytes.
// ---------------------------------------------------------------------------

/** Discriminated type labels for ECIES-encrypted message envelopes. */
export type EciesMessageType = "oauth_token_delivery";

// ---------------------------------------------------------------------------
// buildSignedPayload
// ---------------------------------------------------------------------------

/** Domain-separation label for the OAuth auth-request signature (v4). */
const AUTH_REQUEST_LABEL = Buffer.from("dicode/oauth-auth-request/v4", "utf8");

/** uint32-BE length prefix followed by the field bytes. Length-prefixing
 *  makes the concatenated preimage injective — no field-boundary ambiguity
 *  when a field is added or is variable-length. */
export function lengthPrefixed(field: Buffer): Buffer {
  const len = Buffer.allocUnsafe(4);
  len.writeUInt32BE(field.length);
  return Buffer.concat([len, field]);
}

/**
 * Constructs the byte sequence that the daemon signs when initiating an
 * OAuth flow via the broker. Must match what the daemon constructs exactly.
 *
 * sha256(
 *   "dicode/oauth-auth-request/v4"      (domain label, no prefix)
 *   lp(session_id_bytes)                (16 bytes — UUID v4, hex-decoded, dashes stripped)
 *   lp(pkce_challenge_bytes)            (base64url-decoded)
 *   lp(relay_uuid_bytes)                (32 bytes — 64 hex chars decoded)
 *   lp(provider_utf8_bytes)             (UTF-8 encoded provider name)
 *   timestamp_be_uint64                 (8 bytes, big-endian, fixed-width — no prefix)
 * )
 * where lp(x) = uint32_be(len(x)) || x.
 */
export function buildSignedPayload(
  sessionId: string,
  pkceChallenge: string,
  relayUuid: string,
  provider: string,
  timestamp: number,
): Buffer {
  const ts = Buffer.allocUnsafe(8);
  ts.writeBigUInt64BE(BigInt(timestamp));
  return createHash("sha256")
    .update(AUTH_REQUEST_LABEL)
    .update(lengthPrefixed(Buffer.from(sessionId.replace(/-/g, ""), "hex")))
    .update(lengthPrefixed(Buffer.from(pkceChallenge, "base64url")))
    .update(lengthPrefixed(Buffer.from(relayUuid, "hex")))
    .update(lengthPrefixed(Buffer.from(provider, "utf8")))
    .update(ts)
    .digest();
}

// ---------------------------------------------------------------------------
// verifyECDSA
// ---------------------------------------------------------------------------

/**
 * The fixed 26-byte SPKI DER prefix for `ecPublicKey + prime256v1`. A P-256
 * SPKI is this header followed by the 65-byte uncompressed point. Part of the
 * wire contract — do not replace with an external package without
 * re-verifying byte layout.
 */
export const P256_SPKI_HEADER = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200",
  "hex",
);

/**
 * Wraps a raw 65-byte uncompressed P-256 public key into a DER SubjectPublicKeyInfo.
 * Required by Node.js crypto to import raw EC keys.
 */
export function uncompressedP256ToSpki(pubkey: Buffer): Buffer {
  return Buffer.concat([P256_SPKI_HEADER, pubkey]);
}

/**
 * Verify an ECDSA P-256 signature over `payload`.
 *
 * @param pubkeyBytes  65-byte uncompressed P-256 key (0x04 || X || Y)
 * @param payload      The exact bytes that were signed (output of buildSignedPayload)
 * @param sigDerBase64 Base64-encoded ASN.1 DER signature
 */
export function verifyECDSA(pubkeyBytes: Buffer, payload: Buffer, sigDerBase64: string): boolean {
  try {
    const spki = uncompressedP256ToSpki(pubkeyBytes);
    const verify = createVerify("SHA256");
    verify.update(payload);
    return verify.verify(
      { key: spki, format: "der", type: "spki" },
      Buffer.from(sigDerBase64, "base64"),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// ECIES encryption
// ---------------------------------------------------------------------------

export interface EciesPayload {
  /** Base64-encoded uncompressed P-256 ephemeral public key (65 bytes) */
  ephemeralPubkey: string;
  /**
   * Base64-encoded ciphertext with AES-GCM auth tag appended.
   * The last 16 bytes are the GCM authentication tag.
   * Go daemon splits: ct = decoded[:len-16], tag = decoded[len-16:]
   */
  ciphertext: string;
  /** Base64-encoded 12-byte AES-GCM nonce (IV) */
  nonce: string;
}

/**
 * Encrypt `plaintext` using ECIES for the daemon identified by `daemonPubkeyBytes`.
 *
 * Algorithm:
 *   1. Generate ephemeral P-256 keypair
 *   2. ECDH(ephemeral_priv, daemon_pub) → shared_secret
 *   3. HKDF-SHA256(shared_secret, salt=session_id, info="dicode-oauth-token") → 32-byte enc_key
 *   4. AES-256-GCM encrypt with random 12-byte nonce, binding `messageType`
 *      into the GCM authenticated data so the envelope's Type field cannot
 *      be swapped for a different message type without invalidating the
 *      auth tag. This is domain separation: the same key is never asked
 *      to decrypt two semantically distinct wire formats cleanly.
 *   5. Append 16-byte auth tag to ciphertext
 */
export async function eciesEncrypt(
  daemonPubkeyBytes: Buffer,
  sessionId: string,
  messageType: EciesMessageType,
  plaintext: Buffer,
): Promise<EciesPayload> {
  // messageType is type-enforced via EciesMessageType union — always truthy.
  const eph = createECDH("prime256v1");
  eph.generateKeys();

  // ECDH: ephemeral private × daemon public key
  const sharedSecret = eph.computeSecret(daemonPubkeyBytes);

  // HKDF-SHA256 → 32-byte AES key
  const encKeyRaw = await hkdfAsync(
    "sha256",
    sharedSecret,
    Buffer.from(sessionId),
    "dicode-oauth-token",
    32,
  );
  const encKey = Buffer.from(encKeyRaw);

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encKey, iv);
  cipher.setAAD(Buffer.from(messageType, "utf8"));
  const ctWithoutTag = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes

  // Append auth tag to ciphertext
  const ct = Buffer.concat([ctWithoutTag, authTag]);

  return {
    ephemeralPubkey: eph.getPublicKey("base64"),
    ciphertext: ct.toString("base64"),
    nonce: iv.toString("base64"),
  };
}

// ---------------------------------------------------------------------------
// ECIES decryption (used in tests for round-trip verification)
// ---------------------------------------------------------------------------

/**
 * Decrypt an ECIES payload using the daemon's private key.
 * This mirrors what the Go daemon does on receipt of an oauth_token_delivery message.
 *
 * @param daemonECDH   ECDH instance holding the daemon's private key (prime256v1)
 * @param sessionId    Must match the salt used during encryption
 * @param messageType  Domain-separation label bound into GCM AAD (must match encrypt)
 * @param payload      The EciesPayload from eciesEncrypt
 */
export async function eciesDecrypt(
  daemonECDH: ReturnType<typeof createECDH>,
  sessionId: string,
  messageType: EciesMessageType,
  payload: EciesPayload,
): Promise<Buffer> {
  const ephPubBytes = Buffer.from(payload.ephemeralPubkey, "base64");
  const sharedSecret = daemonECDH.computeSecret(ephPubBytes);

  const encKeyRaw = await hkdfAsync(
    "sha256",
    sharedSecret,
    Buffer.from(sessionId),
    "dicode-oauth-token",
    32,
  );
  const encKey = Buffer.from(encKeyRaw);

  const iv = Buffer.from(payload.nonce, "base64");
  const ciphertextWithTag = Buffer.from(payload.ciphertext, "base64");

  // Split ciphertext and auth tag (last 16 bytes)
  const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);

  const decipher = createDecipheriv("aes-256-gcm", encKey, iv);
  decipher.setAAD(Buffer.from(messageType, "utf8"));
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ---------------------------------------------------------------------------
// ECIES decryption — Web Crypto variant (relay-client / Identity class)
// ---------------------------------------------------------------------------

/**
 * Decrypt an ECIES payload using a Web Crypto ECDH private key.
 *
 * Distinct from the existing eciesDecrypt: that one takes a Node `createECDH`
 * instance, this one takes a Web Crypto `CryptoKey` so it can be called by the
 * relay-client `Identity` class (which stores keys via Web Crypto).
 *
 * Functionally identical: same HKDF info, same AAD binding, same auth-tag
 * convention as eciesEncrypt.
 */
export async function eciesDecryptWebCrypto(
  decryptKey: webcrypto.CryptoKey,
  sessionId: string,
  messageType: EciesMessageType,
  payload: EciesPayload,
): Promise<Buffer> {
  const ephPubBytes = Buffer.from(payload.ephemeralPubkey, "base64");

  // Web Crypto ECDH: import ephemeral pubkey, derive 32-byte secret.
  const ephPub = await crypto.subtle.importKey(
    "raw",
    ephPubBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = Buffer.from(
    await crypto.subtle.deriveBits({ name: "ECDH", public: ephPub }, decryptKey, 256),
  );

  const encKey = Buffer.from(
    await hkdfAsync("sha256", sharedSecret, Buffer.from(sessionId), "dicode-oauth-token", 32),
  );

  const iv = Buffer.from(payload.nonce, "base64");
  const ciphertextWithTag = Buffer.from(payload.ciphertext, "base64");
  const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);

  const decipher = createDecipheriv("aes-256-gcm", encKey, iv);
  decipher.setAAD(Buffer.from(messageType, "utf8"));
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
