/**
 * Stateless OAuth flow-state token.
 *
 * The broker's `/auth/:provider` → `/callback/:provider` state (`Session`) is
 * sealed into a compact AES-256-GCM token carried in the browser's OAuth flow
 * cookie. Sealing/opening is keyed off `BrokerSigningKey.flowStateKey`, which
 * every relay instance derives identically from the shared broker signing key,
 * so a token sealed on one instance opens on any other — the flow survives a
 * load balancer with no shared server-side store or sticky sessions.
 *
 * GCM gives both confidentiality and integrity: a token that has been tampered
 * with (or sealed under a different key) fails `decipher.final()` and opens to
 * `null`. None of the fields are secret (a daemon's own pubkey/uuid/PKCE
 * challenge), but integrity is essential — an attacker must not be able to swap
 * `relayUuid` to redirect a token to their own daemon.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Session } from "./sessions.js";

const FLOW_VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;

interface SerializedFlowState {
  v: number;
  sessionId: string;
  relayUuid: string;
  /** base64 of the 65-byte uncompressed P-256 ECIES recipient key */
  pubkey: string;
  pkceChallenge: string;
  provider: string;
  expiresAt: number;
  scope?: string;
}

/** Seal a `Session` into a URL-safe token for the OAuth flow cookie. */
export function sealFlowState(key: Buffer, session: Session): string {
  const payload: SerializedFlowState = {
    v: FLOW_VERSION,
    sessionId: session.sessionId,
    relayUuid: session.relayUuid,
    pubkey: session.pubkey.toString("base64"),
    pkceChallenge: session.pkceChallenge,
    provider: session.provider,
    expiresAt: session.expiresAt,
    ...(session.scope !== undefined && session.scope !== "" ? { scope: session.scope } : {}),
  };

  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(payload), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString("base64url");
}

/**
 * Open a flow-state token. Returns the `Session` on success, or `null` if the
 * token is malformed, tampered with, sealed under a different key, or carries
 * an unexpected schema. Callers still enforce the TTL and single-use checks.
 */
export function openFlowState(key: Buffer, token: string): Session | null {
  let parsed: unknown;
  try {
    const raw = Buffer.from(token, "base64url");
    if (raw.length < IV_LEN + TAG_LEN) return null;
    const iv = raw.subarray(0, IV_LEN);
    const tag = raw.subarray(raw.length - TAG_LEN);
    const ct = raw.subarray(IV_LEN, raw.length - TAG_LEN);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    parsed = JSON.parse(pt.toString("utf8"));
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const p = parsed as Record<string, unknown>;
  if (
    p.v !== FLOW_VERSION ||
    typeof p.sessionId !== "string" ||
    typeof p.relayUuid !== "string" ||
    typeof p.pubkey !== "string" ||
    typeof p.pkceChallenge !== "string" ||
    typeof p.provider !== "string" ||
    typeof p.expiresAt !== "number" ||
    (p.scope !== undefined && typeof p.scope !== "string")
  ) {
    return null;
  }

  return {
    sessionId: p.sessionId,
    relayUuid: p.relayUuid,
    pubkey: Buffer.from(p.pubkey, "base64"),
    pkceChallenge: p.pkceChallenge,
    provider: p.provider,
    expiresAt: p.expiresAt,
    ...(typeof p.scope === "string" ? { scope: p.scope } : {}),
  };
}
