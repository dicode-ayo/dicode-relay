/**
 * X.509 certificate utilities for the mTLS control channel.
 *
 * The daemon authenticates by presenting a self-signed client certificate
 * wrapping its P-256 signing key; the broker derives the daemon UUID from the
 * certificate's public key. The certificate itself carries no trust — only
 * the SPKI matters — so no CA is involved on the client side.
 *
 * Server side, `generateSelfSignedServerCert` provisions a self-signed leaf
 * for dev / self-hosted brokers; daemons trust it via an explicit CA option.
 */

import { createHash, webcrypto, type X509Certificate } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { P256_SPKI_HEADER } from "./crypto.js";

const P256_SPKI_LEN = P256_SPKI_HEADER.length + 65;

/**
 * Extract the 65-byte uncompressed P-256 public key point from a peer
 * certificate. Returns null when the certificate's key is not P-256
 * (wrong algorithm, wrong curve, compressed point).
 */
export function extractP256PointFromCert(cert: X509Certificate): Buffer | null {
  let spki: Buffer;
  try {
    spki = cert.publicKey.export({ type: "spki", format: "der" });
  } catch {
    return null;
  }
  if (
    spki.length !== P256_SPKI_LEN ||
    !spki.subarray(0, P256_SPKI_HEADER.length).equals(P256_SPKI_HEADER)
  ) {
    return null;
  }
  const point = spki.subarray(P256_SPKI_HEADER.length);
  if (point[0] !== 0x04) {
    return null;
  }
  return Buffer.from(point);
}

/** Derive the daemon UUID from a 65-byte uncompressed P-256 point:
 *  hex(sha256(point)) — 64 lowercase hex chars. Matches Identity.uuid. */
export function uuidFromP256Point(point: Buffer): string {
  return createHash("sha256").update(point).digest("hex");
}

export interface GeneratedCert {
  certPem: string;
  keyPem: string;
}

export interface GenerateServerCertOpts {
  /** SAN hostnames/IPs. "localhost" and "127.0.0.1" are always included. */
  hosts?: string[];
  /** Validity in days. Default 3650. */
  days?: number;
}

const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;

/**
 * Generate a self-signed P-256 server certificate for the mTLS listener.
 *
 * basicConstraints is set to CA:FALSE explicitly: rustls (Deno's TLS stack)
 * rejects CA-flagged certificates presented as end-entity
 * (CaUsedAsEndEntity), so a default openssl-style self-signed CA cert would
 * be unusable by Deno-hosted daemons.
 */
export async function generateSelfSignedServerCert(
  opts: GenerateServerCertOpts = {},
): Promise<GeneratedCert> {
  const days = opts.days ?? 3650;
  const hosts = new Set(["localhost", "127.0.0.1", ...(opts.hosts ?? [])]);

  x509.cryptoProvider.set(webcrypto);
  const keys = await webcrypto.subtle.generateKey(ECDSA_P256, true, ["sign", "verify"]);

  const sans = [...hosts].map((h) =>
    /^\d{1,3}(\.\d{1,3}){3}$/.test(h)
      ? { type: "ip" as const, value: h }
      : { type: "dns" as const, value: h },
  );

  const notBefore = new Date(Date.now() - 5 * 60_000); // clock-skew slack
  const notAfter = new Date(notBefore.getTime() + days * 86_400_000);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: "CN=dicode-relay",
    notBefore,
    notAfter,
    signingAlgorithm: ECDSA_P256,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.SubjectAlternativeNameExtension(sans),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true,
      ),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
    ],
  });

  return {
    certPem: cert.toString("pem"),
    keyPem: await exportPkcs8Pem(keys.privateKey),
  };
}

/**
 * Mint a self-signed client certificate from an existing WebCrypto ECDSA
 * P-256 keypair (the daemon identity's sign key). Only the SPKI matters to
 * the broker; the certificate is regenerated per boot and never persisted.
 */
export async function mintClientCertFromKeys(
  keys: { privateKey: webcrypto.CryptoKey; publicKey: webcrypto.CryptoKey },
  subjectCn: string,
): Promise<GeneratedCert> {
  x509.cryptoProvider.set(webcrypto);
  const notBefore = new Date(Date.now() - 5 * 60_000);
  const notAfter = new Date(notBefore.getTime() + 3650 * 86_400_000);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialHex(),
    name: `CN=${subjectCn}`,
    notBefore,
    notAfter,
    signingAlgorithm: ECDSA_P256,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
    ],
  });
  return {
    certPem: cert.toString("pem"),
    keyPem: await exportPkcs8Pem(keys.privateKey),
  };
}

async function exportPkcs8Pem(priv: webcrypto.CryptoKey): Promise<string> {
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", priv));
  const b64 = pkcs8.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

/** Positive random 16-byte serial, hex-encoded (X.509 serials must be > 0
 *  and DER INTEGERs must not have the high bit set). */
function randomSerialHex(): string {
  const bytes = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16)));
  const first = bytes[0] ?? 0;
  bytes[0] = (first & 0x7f) | 0x01;
  return bytes.toString("hex");
}
