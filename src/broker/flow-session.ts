/**
 * Browser-facing OAuth flow cookie.
 *
 * Grant's Express handler requires `req.session` to persist its per-flow state
 * (`state`, `nonce`, PKCE `code_verifier`) across the provider round-trip.
 * `cookie-session` backs that session with a signed cookie — no server-side
 * store — so the flow survives a load balancer. The same cookie also carries
 * the broker's own sealed flow-state token (`req.session.broker`).
 *
 * The signing keys are derived from the broker signing key so a cookie set by
 * one instance verifies on any other instance behind the load balancer.
 */

import cookieSession from "cookie-session";
import type { RequestHandler } from "express";
import type { BrokerSigningKey } from "../shared/signing.js";

/** Cookie name for the OAuth flow session. */
export const FLOW_COOKIE_NAME = "dicode.oauth";

/** Typed view of the fields we store on the cookie session. */
interface BrokerFlowSession {
  /** Sealed flow-state token (see flow-state.ts). */
  broker?: string | null;
}

/** Read the sealed broker flow-state token from the request's flow cookie. */
export function readBrokerFlow(session: unknown): string | undefined {
  if (typeof session !== "object" || session === null) return undefined;
  const value = (session as BrokerFlowSession).broker;
  return typeof value === "string" ? value : undefined;
}

/** Store the sealed broker flow-state token on the request's flow cookie. */
export function writeBrokerFlow(session: unknown, token: string): void {
  if (typeof session !== "object" || session === null) {
    throw new Error("OAuth flow session middleware not mounted");
  }
  (session as BrokerFlowSession).broker = token;
}

/** Clear the broker flow-state token from the request's flow cookie. */
export function clearBrokerFlow(session: unknown): void {
  if (typeof session === "object" && session !== null) {
    (session as BrokerFlowSession).broker = null;
  }
}

/**
 * Build the cookie-session middleware for the OAuth browser flow.
 *
 * @param brokerKey  broker signing key (its derived `cookieKeys` sign the cookie)
 * @param opts.secure  send the cookie only over HTTPS (true for https base URLs)
 * @param opts.maxAgeMs  cookie lifetime; matches the flow TTL
 */
export function buildFlowSession(
  brokerKey: BrokerSigningKey,
  opts: { secure: boolean; maxAgeMs: number },
): RequestHandler {
  return cookieSession({
    name: FLOW_COOKIE_NAME,
    keys: brokerKey.cookieKeys,
    httpOnly: true,
    sameSite: "lax",
    secure: opts.secure,
    maxAge: opts.maxAgeMs,
  });
}
