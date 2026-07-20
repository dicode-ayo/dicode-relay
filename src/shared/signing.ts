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
  hkdfSync,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { lengthPrefixed } from "./crypto.js";

const AUTO_KEY_FILENAME = "broker-signing-key.pem";

export interface BrokerSigningKey {
  /** Sign sha256(data) with the broker's private key → base64 DER sig */
  sign: (data: Buffer) => string;
  /** Base64-encoded SPKI DER public key (for the welcome message) */
  publicKeyBase64: string;
  /**
   * 32-byte AES-256 key for sealing the stateless OAuth flow-state token
   * (see broker/flow-state.ts). Derived deterministically from the private
   * key so every relay instance behind a load balancer derives the same key
   * and can open a token sealed by any other instance.
   */
  flowStateKey: Buffer;
  /**
   * cookie-session signing keys for the browser-facing OAuth flow cookie
   * (the Grant leg's `req.session`). Derived from the same private key so the
   * cookie a daemon's browser picks up on instance A verifies on instance B.
   */
  cookieKeys: string[];
}

/** HKDF domain label for the AES key that seals the flow-state token. */
const FLOW_STATE_KEY_LABEL = "dicode/oauth-flow-state/v1";
/** HKDF domain label for the cookie-session signing key. */
const FLOW_COOKIE_KEY_LABEL = "dicode/oauth-flow-cookie/v1";

/**
 * Load or generate the broker's signing key.
 *
 * Resolution semantics:
 *   - If `signingKeyFile` is set (from `broker.signing_key_file`), the file
 *     MUST exist; this branch never auto-generates. Operators who land an
 *     explicit path opt into managing the key lifecycle themselves —
 *     auto-generating at a typo'd path would silently rotate the broker
 *     pubkey and invalidate delivery signatures for daemons that have not
 *     reconnected since the rotation (see issue #54).
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
 * @param requireSharedKey   when `true` (from `server.multi_instance`), the
 *                           legacy cwd-fallback is disabled entirely: reaching
 *                           it throws. A per-cwd key — freshly generated or
 *                           read back from an earlier auto-generate — diverges
 *                           across instances, so multi-instance deployments
 *                           must supply one shared key via env or
 *                           `broker.signing_key_file`.
 */
export function loadBrokerSigningKey(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
  signingKeyFile = "",
  allowAutoGenerate = true,
  requireSharedKey = false,
): BrokerSigningKey {
  let pem: string;

  if (env.BROKER_SIGNING_KEY_FILE) {
    pem = readFileSync(env.BROKER_SIGNING_KEY_FILE, "utf8");
  } else if (env.BROKER_SIGNING_KEY) {
    pem = env.BROKER_SIGNING_KEY;
  } else if (signingKeyFile !== "") {
    // A YAML-configured `broker.signing_key_file` was provided. This path is
    // operator-trusted: do NOT auto-generate at it if it's missing — that
    // would mask typos (silently rotating the broker pubkey from a wrong
    // location). Issue #54 tracks a broader hardening of
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
  } else if (requireSharedKey) {
    // Multi-instance mode: the legacy cwd-fallback is a per-instance key, and
    // reading a previously auto-generated one back is just as divergent as
    // minting a fresh one. Refuse both — every instance must present the same
    // broker pubkey or daemons reject broker_sig on token delivery from all
    // but the signing instance.
    throw new Error(
      `server.multi_instance is set but no shared broker signing key was supplied. ` +
        `Every relay instance behind the load balancer must present an identical broker ` +
        `pubkey — otherwise daemons reject the token-delivery signature (broker_sig) from ` +
        `every instance but the one that signed it. Supply one shared P-256 key to all ` +
        `instances via BROKER_SIGNING_KEY_FILE / BROKER_SIGNING_KEY env or ` +
        `broker.signing_key_file, or unset server.multi_instance for single-instance mode.`,
    );
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
      // cwd may be a freshly-created path where the parent directory doesn't
      // yet exist. The YAML-configured path branch above does NOT auto-generate.
      mkdirSync(dirname(autoPath), { recursive: true });
      writeFileSync(autoPath, pair.privateKey, { mode: 0o600 });
      console.warn(
        `broker: no shared signing key configured — generated a per-instance key at ${autoPath}. ` +
          `SINGLE-INSTANCE ONLY: running more than one relay instance with auto-generated keys ` +
          `mints divergent broker pubkeys and daemons reject cross-instance token deliveries. ` +
          `For multi-instance deployments set server.multi_instance: true and hand every ` +
          `instance the same broker.signing_key_file. Set BROKER_SIGNING_KEY_FILE or ` +
          `broker.signing_key_file to pin this key.`,
      );
      pem = pair.privateKey;
    }
  }

  // Derive the public key from the private PEM.
  const { publicKey, privateKey } = loadKeyPair(pem);

  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const publicKeyBase64 = publicKeyDer.toString("base64");

  // Derive the symmetric flow-state / cookie keys from the private key bytes.
  // HKDF with distinct info labels keeps the two purposes independent while
  // remaining deterministic across every instance that loads the same key.
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const emptySalt = Buffer.alloc(0);
  const flowStateKey = Buffer.from(
    hkdfSync("sha256", privDer, emptySalt, FLOW_STATE_KEY_LABEL, 32),
  );
  const cookieKey = Buffer.from(
    hkdfSync("sha256", privDer, emptySalt, FLOW_COOKIE_KEY_LABEL, 32),
  ).toString("base64url");

  return {
    sign(data: Buffer): string {
      const signer = createSign("SHA256");
      signer.update(data);
      return signer.sign(privateKey, "base64");
    },
    publicKeyBase64,
    flowStateKey,
    cookieKeys: [cookieKey],
  };
}

function loadKeyPair(pem: string) {
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(pem);
  return { privateKey, publicKey };
}

/** Domain-separation label for the delivery-envelope signature (v4). */
const DELIVERY_LABEL = Buffer.from("dicode/oauth-token-delivery/v4", "utf8");

/**
 * Build the byte sequence that the broker signs over a delivery envelope.
 * The daemon must reconstruct this exact sequence for verification.
 *
 *   sha256("dicode/oauth-token-delivery/v4"
 *          || lp(type) || lp(session_id) || lp(ephemeral_pubkey)
 *          || lp(ciphertext) || lp(nonce))
 *
 * where lp(x) = uint32_be(len(x)) || x. All fields are UTF-8 encoded
 * (they're already base64/ASCII strings in the envelope JSON); the length
 * prefixes make the variable-length concatenation injective.
 */
export function buildDeliverySignaturePayload(
  type: string,
  sessionId: string,
  ephemeralPubkey: string,
  ciphertext: string,
  nonce: string,
): Buffer {
  const hash = createHash("sha256").update(DELIVERY_LABEL);
  for (const field of [type, sessionId, ephemeralPubkey, ciphertext, nonce]) {
    hash.update(lengthPrefixed(Buffer.from(field, "utf8")));
  }
  return hash.digest();
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
