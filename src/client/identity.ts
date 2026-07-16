import type { webcrypto } from "node:crypto";
import { buildSignedPayload } from "../shared/crypto.js";
import { mintClientCertFromKeys, type GeneratedCert } from "../shared/certs.js";

type JsonWebKey = webcrypto.JsonWebKey;

export interface StoredIdentity {
  sign_priv_pkcs8_b64: string;
  decrypt_priv_pkcs8_b64: string;
}

/** A P-256 key pair backed by Web Crypto. */
interface KeyPair {
  privateKey: webcrypto.CryptoKey;
  publicKey: webcrypto.CryptoKey;
}

export class Identity {
  constructor(
    private signKey: KeyPair,
    private decryptKey: KeyPair,
    public readonly uuid: string,
    public readonly signPubkeyB64: string,
    public readonly decryptPubkeyB64: string,
  ) {}

  /**
   * Generate a fresh split P-256 identity. The caller is responsible for
   * persisting the result of `export()` if they want a stable UUID across
   * runs. UUID is derived as hex(sha256(uncompressed_sign_pubkey)) — 64
   * lowercase hex chars — so a consumer can pre-compute the daemon UUID
   * (and hook URL) before the first handshake, given the export's
   * sign_priv_pkcs8_b64.
   */
  static async generate(): Promise<Identity> {
    const sign = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const decrypt = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);

    const stored: StoredIdentity = {
      sign_priv_pkcs8_b64: abToB64(await crypto.subtle.exportKey("pkcs8", sign.privateKey)),
      decrypt_priv_pkcs8_b64: abToB64(await crypto.subtle.exportKey("pkcs8", decrypt.privateKey)),
    };
    return Identity.fromStored(stored);
  }

  /** Import a previously-exported identity. */
  static async import(stored: StoredIdentity): Promise<Identity> {
    return Identity.fromStored(stored);
  }

  /** Export PKCS8-encoded private keys for persistence. The caller stores
   *  this object via whatever mechanism (kv, file, env, etc.). */
  async export(): Promise<StoredIdentity> {
    return {
      sign_priv_pkcs8_b64: abToB64(await crypto.subtle.exportKey("pkcs8", this.signKey.privateKey)),
      decrypt_priv_pkcs8_b64: abToB64(
        await crypto.subtle.exportKey("pkcs8", this.decryptKey.privateKey),
      ),
    };
  }

  private static async fromStored(s: StoredIdentity): Promise<Identity> {
    const signPriv = await crypto.subtle.importKey(
      "pkcs8",
      b64ToAB(s.sign_priv_pkcs8_b64),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    );
    const decryptPriv = await crypto.subtle.importKey(
      "pkcs8",
      b64ToAB(s.decrypt_priv_pkcs8_b64),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const signPub = await derivePubkey(signPriv, "ECDSA");
    const decryptPub = await derivePubkey(decryptPriv, "ECDH");

    const signRaw = await crypto.subtle.exportKey("raw", signPub);
    const decryptRaw = await crypto.subtle.exportKey("raw", decryptPub);

    const uuidAb = await crypto.subtle.digest("SHA-256", signRaw);
    const uuid = [...new Uint8Array(uuidAb)].map((b) => b.toString(16).padStart(2, "0")).join("");

    return new Identity(
      { privateKey: signPriv, publicKey: signPub },
      { privateKey: decryptPriv, publicKey: decryptPub },
      uuid,
      abToB64(signRaw),
      abToB64(decryptRaw),
    );
  }

  /**
   * Mint a self-signed X.509 client certificate wrapping the sign key, for
   * the broker's mTLS listener. Only the SPKI matters to the broker (it
   * derives uuid = sha256(pubkey) from the peer cert), so the cert is
   * regenerated per boot and never persisted.
   */
  async mintClientCert(): Promise<GeneratedCert> {
    return mintClientCertFromKeys(
      { privateKey: this.signKey.privateKey, publicKey: this.signKey.publicKey },
      this.uuid,
    );
  }

  async signAuthPayload(
    sessionId: string,
    challenge: string,
    provider: string,
    ts: number,
  ): Promise<string> {
    const payloadBuf = buildSignedPayload(sessionId, challenge, this.uuid, provider, ts);
    // `buildSignedPayload` returns sha256(label + fields) — a 32-byte digest.
    // Web Crypto's subtle.sign({hash:"SHA-256"}) hashes its input once internally,
    // so the resulting signature is over sha256(sha256(label + fields)). The broker
    // verifies via Node's createVerify("SHA256").update(buildSignedPayload(...))
    // which also hashes the digest once, giving the same double-hash preimage.
    // Copy into a fresh Uint8Array to satisfy Web Crypto's strict BufferSource constraint.
    const payload = new Uint8Array(payloadBuf);
    const p1363 = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.signKey.privateKey,
      payload,
    );
    return abToB64(p1363ToDer(new Uint8Array(p1363)));
  }

  decryptPrivateKey(): webcrypto.CryptoKey {
    return this.decryptKey.privateKey;
  }
}

// --- low-level helpers ----------------------------------------------------

/** Derive a public key from a private key via JWK round-trip (Web Crypto has no direct API). */
async function derivePubkey(
  priv: webcrypto.CryptoKey,
  alg: "ECDSA" | "ECDH",
): Promise<webcrypto.CryptoKey> {
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  // Build a public-key JWK by omitting the private scalar (d) and key_ops.
  // P-256 keys always have crv/kty/x/y — assert presence to satisfy exactOptionalPropertyTypes.
  if (!jwk.crv || !jwk.kty || !jwk.x || !jwk.y) throw new Error("unexpected JWK shape");
  const pubJwk: JsonWebKey = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  if (jwk.ext !== undefined) pubJwk.ext = jwk.ext;
  return crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: alg, namedCurve: "P-256" },
    true,
    alg === "ECDSA" ? ["verify"] : [],
  );
}

/** Decode base64 to a fresh ArrayBuffer (for Web Crypto consumption). */
function b64ToAB(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const ab = new ArrayBuffer(binary.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return ab;
}

/** Encode an ArrayBuffer to base64. */
function abToB64(ab: ArrayBuffer): string {
  const view = new Uint8Array(ab);
  let s = "";
  for (const byte of view) s += String.fromCharCode(byte);
  return btoa(s);
}

// IEEE P1363 (raw r||s) -> ASN.1 DER (SEQUENCE { INTEGER, INTEGER }) for P-256.
function p1363ToDer(p1363: Uint8Array): ArrayBuffer {
  const r = trimAndPad(p1363.slice(0, 32));
  const s = trimAndPad(p1363.slice(32, 64));
  const seqLen = r.length + s.length + 4;
  const out = new Uint8Array(2 + seqLen);
  let i = 0;
  out[i++] = 0x30;
  out[i++] = seqLen;
  out[i++] = 0x02;
  out[i++] = r.length;
  out.set(r, i);
  i += r.length;
  out[i++] = 0x02;
  out[i++] = s.length;
  out.set(s, i);
  return out.buffer;
}

/** Trim leading zeros and add a zero prefix if high bit is set (for DER INTEGER encoding). */
function trimAndPad(int: Uint8Array): Uint8Array {
  let start = 0;
  while (start < int.length - 1 && int[start] === 0) start++;
  const trimmed = int.slice(start);
  const firstByte = trimmed[0];
  if (firstByte !== undefined && firstByte & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0x00;
    padded.set(trimmed, 1);
    return padded;
  }
  return trimmed;
}
