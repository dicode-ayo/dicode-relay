/**
 * Crypto helpers shared between the relay handshake (`src/relay/server.ts`)
 * and the OAuth broker (`src/broker/crypto.ts`).
 *
 * Kept in a shared module rather than a runtime dependency: the DER wrapping
 * is a fixed 27-byte SPKI prefix specific to ecPublicKey + prime256v1, and
 * we want exact control over the byte layout the daemon expects on the wire.
 */

import { Buffer } from "node:buffer";

/**
 * Fixed 26-byte SPKI header for ecPublicKey + prime256v1 (P-256). When
 * concatenated with a 65-byte uncompressed public key (`0x04 || X || Y`)
 * this yields a 91-byte DER-encoded SubjectPublicKeyInfo that Node's
 * `node:crypto` can import via `createPublicKey({ format: "der", type: "spki" })`.
 */
const P256_SPKI_HEADER = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

/**
 * Wraps a raw 65-byte uncompressed P-256 public key into a DER-encoded
 * SubjectPublicKeyInfo so it can be passed to Node.js `crypto.createVerify`,
 * `crypto.createPublicKey`, and friends.
 */
export function uncompressedP256ToSpki(pubkey: Buffer): Buffer {
  return Buffer.concat([P256_SPKI_HEADER, pubkey]);
}
