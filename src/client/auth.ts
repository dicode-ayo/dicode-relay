import { v4 as uuidv4 } from "uuid";
import type { Identity } from "./identity.js";
import type { OAuthTokenDeliveryPayload } from "../shared/protocol.js";
import { eciesDecryptWebCrypto } from "../shared/crypto.js";
import { verifyDeliverySignature } from "../shared/signing.js";

export interface BuildAuthURLOpts {
  provider: string;
  scope?: string;
  identity: Identity;
  brokerURL: string;
  /** PKCE challenge (base64url(sha256(verifier))). Caller generates the verifier. */
  challenge: string;
}

export interface BuildAuthURLResult {
  url: string;
  sessionId: string;
}

/**
 * Construct the broker /auth/:provider URL, signed by the daemon's SignKey.
 * The caller is responsible for storing the PKCE verifier alongside the
 * sessionId so the eventual token-delivery callback can be correlated.
 */
export async function buildAuthURL(opts: BuildAuthURLOpts): Promise<BuildAuthURLResult> {
  const sessionId = uuidv4();
  const ts = Math.floor(Date.now() / 1000);

  const sigB64 = await opts.identity.signAuthPayload(sessionId, opts.challenge, opts.provider, ts);

  const u = new URL(`/auth/${opts.provider}`, opts.brokerURL);
  u.searchParams.set("session_id", sessionId);
  u.searchParams.set("relay_uuid", opts.identity.uuid);
  u.searchParams.set("pubkey", opts.identity.signPubkeyB64);
  u.searchParams.set("decrypt_pubkey", opts.identity.decryptPubkeyB64);
  u.searchParams.set("challenge", opts.challenge);
  u.searchParams.set("ts", String(ts));
  u.searchParams.set("sig", sigB64);
  if (opts.scope !== undefined) u.searchParams.set("scope", opts.scope);

  return { url: u.toString(), sessionId };
}

/**
 * Verify the broker signature on a delivery envelope and ECIES-decrypt the
 * encrypted token blob. Returns the plaintext token object (provider-specific,
 * typically containing access_token / refresh_token / expires_in / scope).
 *
 * @throws if broker_sig is absent, signature verification fails, or decrypt fails
 */
export async function decryptTokenEnvelope(
  envelope: OAuthTokenDeliveryPayload,
  identity: Identity,
  brokerPubkeyB64: string,
): Promise<Record<string, unknown>> {
  if (envelope.broker_sig === undefined) {
    throw new Error("delivery envelope missing broker_sig");
  }
  const sigOk = verifyDeliverySignature(
    brokerPubkeyB64,
    envelope.broker_sig,
    envelope.type,
    envelope.session_id,
    envelope.ephemeral_pubkey,
    envelope.ciphertext,
    envelope.nonce,
  );
  if (!sigOk) throw new Error("broker signature verification failed");

  const plain = await eciesDecryptWebCrypto(
    identity.decryptPrivateKey(),
    envelope.session_id,
    envelope.type,
    {
      ephemeralPubkey: envelope.ephemeral_pubkey,
      ciphertext: envelope.ciphertext,
      nonce: envelope.nonce,
    },
  );
  return JSON.parse(plain.toString("utf8")) as Record<string, unknown>;
}
