/**
 * Protocol type definitions for the dicode relay WebSocket protocol.
 * Matches PR #79 of dicode-core exactly — do not deviate.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Server → Client messages
// ---------------------------------------------------------------------------

export const ChallengeMessageSchema = z.object({
  type: z.literal("challenge"),
  /** 64 lowercase hex chars (32 bytes of random data) */
  nonce: z
    .string()
    .length(64)
    .regex(/^[0-9a-f]{64}$/),
});

export const WelcomeMessageSchema = z.object({
  type: z.literal("welcome"),
  /** Full WSS URL for this client, e.g. wss://relay.dicode.app/u/<uuid>/hooks/ */
  url: z.url(),
  /** Base64-encoded SPKI DER public key the broker uses to sign delivery envelopes.
   *  Daemons pin this on first connect (TOFU) and verify it on subsequent connects. */
  broker_pubkey: z.string().optional(),
  /** Protocol version announced by the broker. Starts at 2 (dicode-core#104 /
   *  dicode-relay#28): broker understands the split sign/decrypt key model and
   *  will encrypt OAuth tokens to the daemon's decrypt_pubkey when provided.
   *  Daemons that require protocol ≥ 2 for OAuth read this field on welcome. */
  protocol: z.number().int().optional(),
});

export const ErrorMessageSchema = z.object({
  type: z.literal("error"),
  message: z.string(),
});

/**
 * Inbound request forwarded from an HTTP caller to the daemon.
 * Body is base64-encoded bytes.
 */
export const RequestMessageSchema = z.object({
  type: z.literal("request"),
  /** UUIDv4 used to correlate the response */
  id: z.uuid(),
  method: z.string(),
  path: z.string(),
  headers: z.record(z.string(), z.array(z.string())),
  /** Base64-encoded request body */
  body: z.string(),
});

// ---------------------------------------------------------------------------
// Client → Server messages
// ---------------------------------------------------------------------------

export const HelloMessageSchema = z.object({
  type: z.literal("hello"),
  /** hex(sha256(uncompressed_pubkey)) — 64 lowercase hex chars */
  uuid: z
    .string()
    .length(64)
    .regex(/^[0-9a-f]{64}$/),
  /** Base64 std-encoded 65-byte uncompressed P-256 public key (0x04 || X || Y).
   *  Used for ECDSA verification (WSS handshake + /auth/:provider sigs). */
  pubkey: z.string(),
  /** Base64 std-encoded 65-byte uncompressed P-256 public key (0x04 || X || Y).
   *  Used as the ECIES recipient on OAuth token delivery (dicode-core#104).
   *  Required: every daemon now ships with a split sign/decrypt identity. */
  decrypt_pubkey: z.string(),
  /** Base64 std-encoded ECDSA P-256 ASN.1 DER signature */
  sig: z.string(),
  /** Unix timestamp in seconds */
  timestamp: z.number().int(),
});

/**
 * Response from the daemon to a forwarded request.
 */
export const ResponseMessageSchema = z.object({
  type: z.literal("response"),
  /** Matches the `id` from the corresponding RequestMessage */
  id: z.uuid(),
  status: z.number().int().min(100).max(599),
  headers: z.record(z.string(), z.array(z.string())),
  /** Base64-encoded response body */
  body: z.string(),
});

// ---------------------------------------------------------------------------
// TypeScript types derived from Zod schemas
// ---------------------------------------------------------------------------

export type ChallengeMessage = z.infer<typeof ChallengeMessageSchema>;
export type WelcomeMessage = z.infer<typeof WelcomeMessageSchema>;
export type ErrorMessage = z.infer<typeof ErrorMessageSchema>;
export type RequestMessage = z.infer<typeof RequestMessageSchema>;
export type HelloMessage = z.infer<typeof HelloMessageSchema>;
export type ResponseMessage = z.infer<typeof ResponseMessageSchema>;

/** Any message the server sends to the client */
export type ServerMessage = ChallengeMessage | WelcomeMessage | ErrorMessage | RequestMessage;

/** Any message the client sends to the server */
export type ClientMessage = HelloMessage | ResponseMessage;

// ---------------------------------------------------------------------------
// ECIES token delivery payload (broker → daemon via relay)
// ---------------------------------------------------------------------------

export interface OAuthTokenDeliveryPayload {
  type: "oauth_token_delivery";
  session_id: string;
  /** Base64-encoded uncompressed P-256 ephemeral public key (65 bytes) */
  ephemeral_pubkey: string;
  /**
   * Base64-encoded ciphertext.
   * IMPORTANT: The last 16 bytes of the decoded ciphertext are the AES-GCM
   * authentication tag. The Go daemon must split them off before calling
   * aesGCM.Open:
   *   ct := decoded[:len(decoded)-16]
   *   tag := decoded[len(decoded)-16:]
   */
  ciphertext: string;
  /** Base64-encoded 12-byte AES-GCM nonce (IV) */
  nonce: string;
  /**
   * Base64-encoded ECDSA P-256 signature over
   * sha256(type || session_id || ephemeral_pubkey || ciphertext || nonce).
   * Signed by the broker's long-lived key whose public half is announced
   * in the WSS welcome message. Proves the envelope was assembled by a
   * trusted broker, not a forger who merely knows the daemon's public key.
   */
  broker_sig?: string;
}
