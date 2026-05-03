import type { webcrypto } from "node:crypto";
import { buildSignedPayload } from "../shared/crypto.js";

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

  /** Generate a fresh split P-256 identity. The caller is responsible for
   *  persisting the result of `export()` if they want a stable UUID across runs. */
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

  async signChallenge(nonceHex: string, ts: number): Promise<string> {
    const nonce = hexToAB(nonceHex);
    const tsBuf = new DataView(new ArrayBuffer(8));
    tsBuf.setBigUint64(0, BigInt(ts), false);
    const msg = concatAB(nonce, tsBuf.buffer);
    // Web Crypto's subtle.sign({hash: "SHA-256"}) hashes the input internally — pass raw bytes, not a pre-computed digest.
    const p1363 = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.signKey.privateKey,
      msg,
    );
    return abToB64(p1363ToDer(new Uint8Array(p1363)));
  }

  async signAuthPayload(
    sessionId: string,
    challenge: string,
    provider: string,
    ts: number,
  ): Promise<string> {
    const payloadBuf = buildSignedPayload(sessionId, challenge, this.uuid, provider, ts);
    // `buildSignedPayload` returns sha256(fields) — a 32-byte digest.
    // Web Crypto's subtle.sign({hash:"SHA-256"}) hashes its input once internally,
    // so the resulting signature is over sha256(sha256(fields)). The broker verifies
    // via Node's createVerify("SHA256").update(buildSignedPayload(...)) which also
    // hashes the digest once, giving the same sha256(sha256(fields)) preimage.
    // This matches the Go reference (pkg/relay/oauth.go SignAuthPayload).
    // Copy into a fresh Uint8Array to satisfy Web Crypto's strict BufferSource constraint.
    const payload = new Uint8Array(payloadBuf);
    const p1363 = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      this.signKey.privateKey,
      payload,
    );
    return abToB64(p1363ToDer(new Uint8Array(p1363)));
  }

  async verifyOwnSignature(nonceHex: string, ts: number, sigDerB64: string): Promise<boolean> {
    const nonce = hexToAB(nonceHex);
    const tsBuf = new DataView(new ArrayBuffer(8));
    tsBuf.setBigUint64(0, BigInt(ts), false);
    const msg = concatAB(nonce, tsBuf.buffer);
    const sig = derToP1363(new Uint8Array(b64ToAB(sigDerB64)));
    // Web Crypto's subtle.verify({hash: "SHA-256"}) hashes the input internally — pass raw bytes, not a pre-computed digest.
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      this.signKey.publicKey,
      sig,
      msg,
    );
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

/** Decode a hex string to a fresh ArrayBuffer. */
function hexToAB(hex: string): ArrayBuffer {
  const ab = new ArrayBuffer(hex.length / 2);
  const view = new Uint8Array(ab);
  for (let i = 0; i < view.length; i++) {
    view[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return ab;
}

/** Concatenate two ArrayBuffers. */
function concatAB(a: ArrayBuffer, b: ArrayBuffer): ArrayBuffer {
  const out = new ArrayBuffer(a.byteLength + b.byteLength);
  const view = new Uint8Array(out);
  view.set(new Uint8Array(a), 0);
  view.set(new Uint8Array(b), a.byteLength);
  return out;
}

// IEEE P1363 (raw r||s) <-> ASN.1 DER (SEQUENCE { INTEGER, INTEGER }) for P-256.
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

function derToP1363(der: Uint8Array): ArrayBuffer {
  if (der[0] !== 0x30) throw new Error("not a DER SEQUENCE");
  // P-256 ECDSA signatures are always ≤ 72 bytes, so the SEQUENCE length is
  // always single-byte (< 0x80). Reject multi-byte length encodings as malformed.
  if (der[1] === undefined || der[1] >= 0x80) throw new Error("invalid DER length");
  let i = 2;
  if (der[i] !== 0x02) throw new Error("expected INTEGER for r");
  i++;
  const rLen = der[i];
  if (rLen === undefined) throw new Error("truncated DER: missing r length");
  i++;
  const r = der.slice(i, i + rLen);
  i += rLen;
  if (der[i] !== 0x02) throw new Error("expected INTEGER for s");
  i++;
  const sLen = der[i];
  if (sLen === undefined) throw new Error("truncated DER: missing s length");
  i++;
  const s = der.slice(i, i + sLen);
  const out = new ArrayBuffer(64);
  const view = new Uint8Array(out);
  view.set(padTo32(r), 0);
  view.set(padTo32(s), 32);
  return out;
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

/** Remove DER INTEGER leading zeros and zero-pad to 32 bytes for P1363. */
function padTo32(int: Uint8Array): Uint8Array {
  let start = 0;
  while (start < int.length - 1 && int[start] === 0) start++;
  const trimmed = int.slice(start);
  if (trimmed.length === 32) return trimmed;
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}
