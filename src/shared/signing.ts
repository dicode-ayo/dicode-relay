/**
 * Broker signing key — proves delivery envelopes were assembled by this
 * relay instance, not by a forger who knows the daemon's public key.
 *
 * Key resolution order (first hit wins):
 *   1. BROKER_SIGNING_KEY_FILE env → read PEM from file
 *   2. BROKER_SIGNING_KEY env → inline PEM string
 *   3. broker.signing_key_file from relay.yaml → read PEM from file
 *      (must exist; does NOT auto-generate — see loadBrokerSigningKey)
 *   4. Auto-generate to <cwd>/broker-signing-key.pem on first start
 *
 * Env takes precedence over YAML so operators can override a baked-in
 * config without re-rendering the file (e.g. in containers / k8s secrets).
 *
 * The key is ECDSA P-256 (same curve family as the daemon identity, but a
 * completely separate keypair). Only the relay holds the private half; the
 * public half is announced to every connecting daemon in the WSS welcome
 * message so they can verify delivery signatures.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

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
 * Resolution semantics:
 *   - If `signingKeyFile` is set (from `broker.signing_key_file`), the file
 *     MUST exist; this branch never auto-generates. Operators who land an
 *     explicit path opt into managing the key lifecycle themselves —
 *     auto-generating at a typo'd path would silently rotate the broker
 *     pubkey and break every TOFU-pinned daemon (see issue #54).
 *   - If no env/inline/YAML source is set, the legacy cwd fallback at
 *     `<cwd>/broker-signing-key.pem` is consulted; on first start it is
 *     auto-generated (with `mkdir -p` for the parent dir, in case cwd's
 *     parent doesn't exist yet).
 *
 * @param env                process.env (or test override)
 * @param cwd                working directory for auto-generated key fallback
 * @param signingKeyFile     `broker.signing_key_file` from relay.yaml (or "" if unset)
 * @param allowAutoGenerate  when no env/file source is present, controls the
 *                           legacy cwd-fallback: `true` (default — legacy CLI
 *                           behavior) persists a freshly generated key to
 *                           `<cwd>/broker-signing-key.pem`; `false` returns an
 *                           in-memory ephemeral key without touching disk.
 *                           `startServer({ dryRun: true })` passes `false` so
 *                           config-validation runs never write secret material
 *                           into the caller's cwd.
 */
export function loadBrokerSigningKey(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
  signingKeyFile = "",
  allowAutoGenerate = true,
): BrokerSigningKey {
  let pem: string;

  if (env.BROKER_SIGNING_KEY_FILE) {
    pem = readFileSync(env.BROKER_SIGNING_KEY_FILE, "utf8");
  } else if (env.BROKER_SIGNING_KEY) {
    pem = env.BROKER_SIGNING_KEY;
  } else if (signingKeyFile !== "") {
    // A YAML-configured `broker.signing_key_file` was provided. This path is
    // operator-trusted: do NOT auto-generate at it if it's missing — that
    // would mask typos (rotating the broker pubkey to a wrong location and
    // breaking TOFU-pinned daemons). Issue #54 tracks a broader hardening of
    // when auto-gen is allowed to fire at all. Surface ENOENT with a clear
    // message naming the path so operators can spot the typo or pre-create
    // the file via their orchestration layer.
    if (!existsSync(signingKeyFile)) {
      throw new Error(
        `broker.signing_key_file points to a missing file: ${signingKeyFile}. ` +
          `Either create the file (e.g. generate a P-256 PEM with openssl) or ` +
          `unset broker.signing_key_file to fall back to auto-generation.`,
      );
    }
    pem = readFileSync(signingKeyFile, "utf8");
  } else {
    // No env, no inline key, no YAML path. Fall back to the legacy
    // cwd-relative location and auto-generate on first start.
    const autoPath = join(cwd, AUTO_KEY_FILENAME);
    if (existsSync(autoPath)) {
      pem = readFileSync(autoPath, "utf8");
    } else if (!allowAutoGenerate) {
      // dryRun / library-validation path: derive an ephemeral key in-memory
      // so the broker router can still wire up, but never persist it. The
      // returned key is thrown away when the StartHandle is closed.
      const pair = generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      pem = pair.privateKey;
    } else {
      const pair = generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      // Safety: cwd may itself be a freshly-created path where the parent
      // directory doesn't yet exist. mkdir -p before writeFileSync so we
      // don't throw ENOENT on the legacy fallback. This is the narrow fix
      // the original brief intended — the YAML-configured path branch
      // above deliberately does NOT auto-generate (see #54 for context).
      mkdirSync(dirname(autoPath), { recursive: true });
      writeFileSync(autoPath, pair.privateKey, { mode: 0o600 });
      console.warn(
        `broker: generated signing key at ${autoPath} — ` +
          `set BROKER_SIGNING_KEY_FILE or broker.signing_key_file to use a persistent key`,
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
  const payload = buildDeliverySignaturePayload(
    type,
    sessionId,
    ephemeralPubkey,
    ciphertext,
    nonce,
  );
  const verifier = createVerify("SHA256");
  verifier.update(payload);
  return verifier.verify(
    { key: pubKeyDer, format: "der", type: "spki" },
    Buffer.from(sig, "base64"),
  );
}
