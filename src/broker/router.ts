/**
 * OAuth broker Express router.
 *
 * Routes:
 *   GET /auth/:provider   — validate daemon signature, create session, redirect to Grant
 *   GET /callback/:provider — (handled by Grant middleware, then picked up here)
 *
 * After Grant completes the OAuth code exchange, it calls back into the session
 * store to find the daemon, encrypts the token with ECIES, and forwards it over
 * the relay WebSocket.
 */

import { Router, type Request, type Response } from "express";
import { v4 as uuidv4 } from "uuid";
import type { RelayServer } from "../relay/server.js";
import { buildSignedPayload, eciesEncrypt, verifyECDSA } from "./crypto.js";
import type { ProviderConfig } from "./providers.js";
import type { SessionStore } from "./sessions.js";
import type { OAuthTokenDeliveryPayload } from "../relay/protocol.js";

const TIMESTAMP_TOLERANCE_S = 30;

/**
 * Build the Express router for the OAuth broker.
 *
 * @param relay     RelayServer instance — used to look up clients and forward tokens
 * @param sessions  SessionStore instance
 * @param providers Enabled provider map (from config, already resolved)
 */
export function buildBrokerRouter(
  relay: RelayServer,
  sessions: SessionStore,
  providers: ReadonlyMap<string, ProviderConfig>,
): Router {
  const router = Router();

  // -------------------------------------------------------------------------
  // GET /auth/:provider
  // -------------------------------------------------------------------------
  // Validates the daemon's signed request and creates a session.
  // Then redirects to Grant's /connect/:provider route to start the OAuth dance.
  //
  // Expected query params:
  //   session    — UUID v4 session ID
  //   challenge  — base64url PKCE challenge
  //   relay_uuid — 64 hex chars (daemon identity)
  //   sig        — base64 ECDSA signature over buildSignedPayload(...)
  //   timestamp  — Unix seconds
  //   scope      — (optional) space-separated scope override
  // -------------------------------------------------------------------------

  router.get("/auth/:provider", (req: Request, res: Response): void => {
    const provider = req.params.provider as string | undefined;
    if (provider === undefined) {
      res.status(400).json({ error: "missing provider" });
      return;
    }

    if (!providers.has(provider)) {
      res.status(404).json({ error: `unknown provider: ${provider}` });
      return;
    }

    const query = req.query as Record<string, string | string[] | undefined>;
    const session = Array.isArray(query.session) ? query.session[0] : query.session;
    const challenge = Array.isArray(query.challenge) ? query.challenge[0] : query.challenge;
    const relay_uuid = Array.isArray(query.relay_uuid) ? query.relay_uuid[0] : query.relay_uuid;
    const sig = Array.isArray(query.sig) ? query.sig[0] : query.sig;
    const timestamp = Array.isArray(query.timestamp) ? query.timestamp[0] : query.timestamp;
    const scope = Array.isArray(query.scope) ? query.scope[0] : query.scope;

    if (session === undefined || session === "") {
      res.status(400).json({ error: "missing session" });
      return;
    }
    if (challenge === undefined || challenge === "") {
      res.status(400).json({ error: "missing challenge" });
      return;
    }
    if (relay_uuid === undefined || relay_uuid === "") {
      res.status(400).json({ error: "missing relay_uuid" });
      return;
    }
    if (sig === undefined || sig === "") {
      res.status(400).json({ error: "missing sig" });
      return;
    }
    if (timestamp === undefined || timestamp === "") {
      res.status(400).json({ error: "missing timestamp" });
      return;
    }

    // Validate relay_uuid format (64 hex chars)
    if (!/^[0-9a-f]{64}$/.test(relay_uuid)) {
      res.status(400).json({ error: "invalid relay_uuid format" });
      return;
    }

    // Validate timestamp freshness
    const ts = parseInt(timestamp, 10);
    if (!Number.isFinite(ts)) {
      res.status(400).json({ error: "invalid timestamp" });
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > TIMESTAMP_TOLERANCE_S) {
      res.status(403).json({ error: "timestamp out of range" });
      return;
    }

    // Look up daemon in relay client registry
    let client: ReturnType<RelayServer["getClient"]>;
    try {
      client = relay.getClient(relay_uuid);
    } catch {
      res.status(403).json({ error: "daemon not connected" });
      return;
    }

    // Verify ECDSA signature
    const payload = buildSignedPayload(session, challenge, relay_uuid, provider, ts);
    if (!verifyECDSA(client.pubkey, payload, sig)) {
      res.status(403).json({ error: "invalid signature" });
      return;
    }

    // Store session
    sessions.set({
      sessionId: session,
      relayUuid: relay_uuid,
      pubkey: client.pubkey,
      pkceChallenge: challenge,
      provider,
      expiresAt: Date.now() + 5 * 60 * 1000,
      ...(scope !== undefined && scope !== "" ? { scope } : {}),
    });

    // Redirect to Grant's connect route (relative redirect).
    // Grant dynamic fields: scope and state are passed as query params.
    const redirectPath =
      `/connect/${provider}?state=${encodeURIComponent(session)}` +
      (scope !== undefined && scope !== "" ? `&scope=${encodeURIComponent(scope)}` : "");
    res.redirect(302, redirectPath);
  });

  // -------------------------------------------------------------------------
  // GET /callback/:provider (Grant callback handler)
  // -------------------------------------------------------------------------
  // Grant handles the code exchange and appends the token to the request.
  // We pick it up here to encrypt and deliver to the daemon.
  // -------------------------------------------------------------------------

  router.get("/callback/:provider", (req: Request, res: Response): void => {
    // Grant appends the session to req.query.state, and the token to req.query.access_token
    // The actual Grant callback is handled by Grant middleware before this route,
    // which populates req.session or passes via query. With transport: 'querystring',
    // Grant redirects to this callback URL with the token as query params.
    void handleCallback(req, res, relay, sessions);
  });

  return router;
}

async function handleCallback(
  req: Request,
  res: Response,
  relay: RelayServer,
  sessions: SessionStore,
): Promise<void> {
  const rawQuery = req.query as Record<string, string | string[] | undefined>;
  const state = Array.isArray(rawQuery.state) ? rawQuery.state[0] : rawQuery.state;
  const access_token = Array.isArray(rawQuery.access_token)
    ? rawQuery.access_token[0]
    : rawQuery.access_token;
  const error = Array.isArray(rawQuery.error) ? rawQuery.error[0] : rawQuery.error;

  if (error !== undefined) {
    res.status(400).send(`<html><body><p>OAuth error: ${escapeHtml(error)}</p></body></html>`);
    return;
  }

  if (state === undefined || access_token === undefined) {
    res.status(400).send("<html><body><p>Missing state or token</p></body></html>");
    return;
  }

  const session = sessions.get(state);
  if (session === undefined) {
    res.status(400).send("<html><body><p>Session expired or not found</p></body></html>");
    return;
  }

  // Build the token payload (include all grant-returned fields)
  // Remove state from token data to avoid leaking session metadata
  const rawTokenData = req.query as Record<string, unknown>;
  const tokensToDeliver = Object.fromEntries(
    Object.entries(rawTokenData).filter(([k]) => k !== "state"),
  );

  // Encrypt the token payload with ECIES for the daemon
  const plaintext = Buffer.from(JSON.stringify(tokensToDeliver));
  let encrypted: Awaited<ReturnType<typeof eciesEncrypt>>;
  try {
    encrypted = await eciesEncrypt(session.pubkey, session.sessionId, plaintext);
  } catch {
    res.status(500).send("<html><body><p>Encryption failed</p></body></html>");
    return;
  }

  const deliveryPayload: OAuthTokenDeliveryPayload = {
    type: "oauth_token_delivery",
    session_id: session.sessionId,
    ephemeral_pubkey: encrypted.ephemeralPubkey,
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
  };

  // Delete session immediately (single-use)
  sessions.delete(session.sessionId);

  // Forward to daemon via relay
  const requestId = uuidv4();
  try {
    await relay.forward(
      session.relayUuid,
      "POST",
      "/hooks/oauth-complete",
      { "Content-Type": ["application/json"], "X-Dicode-Request-Id": [requestId] },
      Buffer.from(JSON.stringify(deliveryPayload)),
    );
    res
      .status(200)
      .send("<html><body><p>Authorization complete. You may close this tab.</p></body></html>");
  } catch {
    res
      .status(503)
      .send("<html><body><p>Daemon not connected. Please retry the OAuth flow.</p></body></html>");
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}
