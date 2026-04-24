/**
 * Protocol type re-exports and conversion helpers.
 *
 * The canonical schema lives in `proto/relay.proto` and is regenerated into
 * `./pb/relay_pb.ts` by `buf generate`. This module keeps a small surface of
 * re-exports and boundary conversions so callers (RelayServer consumers,
 * broker router) don't need to know about HeaderValues wrappers or the
 * oneof-envelope shape.
 */

import type {
  ChallengeSchema,
  ClientMessageSchema,
  ErrorSchema,
  HeaderValuesSchema,
  HelloSchema,
  RequestSchema,
  ResponseSchema,
  ServerMessageSchema,
  WelcomeSchema,
} from "./pb/relay_pb.js";
import type { MessageShape } from "@bufbuild/protobuf";

export type ClientMessage = MessageShape<typeof ClientMessageSchema>;
export type ServerMessage = MessageShape<typeof ServerMessageSchema>;

export type ChallengeMessage = MessageShape<typeof ChallengeSchema>;
export type HelloMessage = MessageShape<typeof HelloSchema>;
export type WelcomeMessage = MessageShape<typeof WelcomeSchema>;
export type ErrorMessage = MessageShape<typeof ErrorSchema>;
export type RequestMessage = MessageShape<typeof RequestSchema>;
export type ResponseMessage = MessageShape<typeof ResponseSchema>;
export type HeaderValues = MessageShape<typeof HeaderValuesSchema>;

/**
 * OAuthTokenDeliveryPayload is the JSON body the broker POSTs to the daemon's
 * `/hooks/oauth-complete` webhook. It is transported INSIDE the tunnel's
 * Request.body (base64-encoded) and is NOT itself a ServerMessage variant —
 * so it stays hand-typed in TS to mirror the matching Go struct
 * (pkg/relay/oauth.go `OAuthTokenDeliveryPayload`).
 *
 * The ciphertext has the 16-byte AES-GCM authentication tag appended; the
 * daemon splits the last 16 bytes off before passing to aesGCM.Open.
 */
export interface OAuthTokenDeliveryPayload {
  type: "oauth_token_delivery";
  session_id: string;
  /** Base64-encoded uncompressed P-256 ephemeral public key (65 bytes). */
  ephemeral_pubkey: string;
  /** Base64-encoded ciphertext with auth tag appended. */
  ciphertext: string;
  /** Base64-encoded 12-byte AES-GCM nonce (IV). */
  nonce: string;
  /** Base64-encoded ECDSA P-256 signature over
   *  sha256(type || session_id || ephemeral_pubkey || ciphertext || nonce).
   *  Signed by the broker's long-lived key announced in Welcome.broker_pubkey. */
  broker_sig?: string;
}

/**
 * ForwardResponse is what RelayServer.forward() resolves to. Callers get the
 * pre-proto shape (flat headers) so they don't have to unwrap HeaderValues.
 * The `id` is dropped because the caller always already knows it.
 */
export interface ForwardResponse {
  status: number;
  headers: Record<string, string[]>;
  body: string; // base64
}
