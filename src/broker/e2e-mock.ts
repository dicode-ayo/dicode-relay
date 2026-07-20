/**
 * E2E mock OAuth provider — gated behind DICODE_E2E_MOCK_PROVIDER=1.
 * Must never mount in production.
 *
 * Exposes two endpoints, both useful for exercising the broker→daemon token
 * delivery path end-to-end without any real upstream OAuth provider:
 *
 *   GET /connect/mock
 *     Short-circuits the upstream authorize + code-exchange steps. Reads
 *     `state` (the session ID created by /auth/mock), looks up the session,
 *     and redirects the browser to /callback/mock?state=…&access_token=…
 *     The existing /callback/:provider handler then encrypts and forwards
 *     the synthetic token to the daemon. Lets a test driver exercise the
 *     full daemon-issued build_auth_url → browser → broker → daemon
 *     round-trip.
 *
 *   POST /_test/deliver
 *     A lower-level primitive that bypasses /auth and /connect entirely.
 *     Takes { uuid, session_id, provider, tokens } directly, builds the
 *     ECIES envelope using the connected daemon's decrypt pubkey + the
 *     broker signing key, and forwards. Used for cross-implementation
 *     wire-shape testing.
 */

import type { Request, Response, Router } from "express";
import { Router as makeRouter, json } from "express";
import { eciesEncrypt } from "../shared/crypto.js";
import type { OAuthTokenDeliveryPayload } from "../shared/protocol.js";
import type { RelayServer } from "../relay/server.js";
import { openFlowState } from "./flow-state.js";
import { clearBrokerFlow, readBrokerFlow } from "./flow-session.js";
import { buildDeliverySignaturePayload, type BrokerSigningKey } from "../shared/signing.js";

/** Provider key used throughout the mock flow. */
export const MOCK_PROVIDER_KEY = "mock";

/**
 * Whether the E2E mock provider is enabled for this process.
 *
 * Fails closed when `NODE_ENV=production` even if the flag is set — the
 * mock endpoints hand out daemon-decryptable token deliveries to anyone
 * who can reach the HTTP port, so the consequence of an accidentally
 * enabled flag in prod is "attacker writes chosen OAuth tokens into any
 * connected daemon's secret store." The NODE_ENV refusal converts the
 * operator-must-remember invariant into an enforced one.
 *
 * The NODE_ENV match is case-insensitive and whitespace-tolerant so that
 * oddly-capitalised or copy-pasted values like "PRODUCTION" or
 * " production" still trip the refusal.
 *
 * Accepts an explicit `env` so library callers (`startServer({ env })`) can
 * scope the mock decision to their supplied env without inheriting flags
 * from the host `process.env`. Defaults to `process.env` for legacy callers.
 */
export function isE2EMockEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const nodeEnv = env.NODE_ENV?.trim().toLowerCase();
  if (nodeEnv === "production") return false;
  return env.DICODE_E2E_MOCK_PROVIDER === "1";
}

interface DeliverBody {
  uuid: string;
  session_id: string;
  provider: string;
  tokens: Record<string, unknown>;
}

/**
 * Build the Express router for the E2E mock provider.
 *
 * Mount BEFORE the Grant middleware so /connect/mock is handled here and
 * Grant never sees it, and BEFORE the broker router so /_test/deliver
 * is reachable.
 */
export function buildE2EMockRouter(relay: RelayServer, brokerKey: BrokerSigningKey): Router {
  const router: Router = makeRouter();

  router.get("/connect/mock", (req: Request, res: Response) => {
    handleConnectMock(req, res, brokerKey);
  });

  // json() is scoped to this route only. The router mounts at the app root
  // before Grant, so a global json() would consume bodies on unrelated routes.
  router.post("/_test/deliver", json(), (req: Request, res: Response) => {
    void handleDeliver(req, res, relay, brokerKey);
  });

  return router;
}

function handleConnectMock(req: Request, res: Response, brokerKey: BrokerSigningKey): void {
  const rawState = req.query.state;
  const state = Array.isArray(rawState) ? rawState[0] : rawState;
  if (typeof state !== "string" || state === "") {
    res.status(400).send("missing state");
    return;
  }

  // Recover the flow state from the sealed cookie set by /auth/mock.
  const token = readBrokerFlow(req.session);
  const session = token !== undefined ? openFlowState(brokerKey.flowStateKey, token) : null;
  if (session === null) {
    res.status(400).send("session not found");
    return;
  }
  if (session.sessionId !== state) {
    res.status(400).send("session mismatch");
    return;
  }
  if (session.provider !== MOCK_PROVIDER_KEY) {
    res.status(400).send("session is not for mock provider");
    return;
  }
  if (session.expiresAt <= Date.now()) {
    clearBrokerFlow(req.session);
    res.status(400).send("session expired");
    return;
  }

  const callbackPath =
    `/callback/${MOCK_PROVIDER_KEY}` +
    `?state=${encodeURIComponent(state)}` +
    `&access_token=${encodeURIComponent(`mock-token-${state}`)}` +
    `&token_type=bearer`;
  res.setHeader("Referrer-Policy", "no-referrer");
  res.redirect(302, callbackPath);
}

function isPlainTokensObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function handleDeliver(
  req: Request,
  res: Response,
  relay: RelayServer,
  brokerKey: BrokerSigningKey,
): Promise<void> {
  const body = req.body as Partial<DeliverBody>;
  if (
    typeof body.uuid !== "string" ||
    body.uuid === "" ||
    typeof body.session_id !== "string" ||
    body.session_id === "" ||
    typeof body.provider !== "string" ||
    body.provider === "" ||
    !isPlainTokensObject(body.tokens)
  ) {
    res.status(400).json({ error: "uuid, session_id, provider, tokens required" });
    return;
  }

  if (!relay.hasClient(body.uuid)) {
    res.status(404).json({ error: "daemon uuid not connected to relay" });
    return;
  }
  const client = relay.getClient(body.uuid);

  const deliveryType = "oauth_token_delivery";
  const plaintext = Buffer.from(JSON.stringify(body.tokens));

  let encrypted: Awaited<ReturnType<typeof eciesEncrypt>>;
  try {
    encrypted = await eciesEncrypt(client.decryptPubkey, body.session_id, deliveryType, plaintext);
  } catch (e) {
    console.error("e2e-mock: encrypt failed", e);
    res.status(500).json({ error: "encrypt failed" });
    return;
  }

  const payload: OAuthTokenDeliveryPayload = {
    type: deliveryType,
    session_id: body.session_id,
    ephemeral_pubkey: encrypted.ephemeralPubkey,
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
  };

  const sigPayload = buildDeliverySignaturePayload(
    payload.type,
    payload.session_id,
    payload.ephemeral_pubkey,
    payload.ciphertext,
    payload.nonce,
  );
  payload.broker_sig = brokerKey.sign(sigPayload);

  try {
    const daemonResp = await relay.forward(
      body.uuid,
      "POST",
      "/hooks/oauth-complete",
      { "Content-Type": ["application/json"] },
      Buffer.from(JSON.stringify(payload)),
    );
    // Return only the daemon's HTTP status. The body is intentionally NOT
    // reflected back — the caller already knows what they sent and the
    // daemon's reply may contain noisy or sensitive error context.
    res.status(200).json({ daemon_status: daemonResp.status });
  } catch (e) {
    console.error("e2e-mock: forward failed", e);
    res.status(502).json({ error: "forward failed" });
  }
}
