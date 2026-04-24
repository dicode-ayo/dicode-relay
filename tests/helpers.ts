/**
 * Shared test helpers. All defaults come from the Zod config schema
 * so tests never duplicate magic numbers.
 */

import { defaultConfig } from "../src/config.js";
import type { RelayServerOptions } from "../src/relay/server.js";

const cfg = defaultConfig();

/** Relay server options with all Zod defaults — merge with test overrides. */
export function testRelayOpts(overrides?: Partial<RelayServerOptions>): RelayServerOptions {
  return {
    baseUrl: "ws://localhost",
    timestampToleranceS: cfg.relay.timestamp_tolerance_s,
    pingIntervalMs: cfg.relay.ping_interval_ms,
    pongTimeoutMs: cfg.relay.pong_timeout_ms,
    requestTimeoutMs: cfg.relay.request_timeout_ms,
    nonceTtlMs: cfg.relay.nonce_ttl_ms,
    ...overrides,
  };
}

/** Session TTL from Zod defaults. */
export const testSessionTtlMs = cfg.broker.session_ttl_ms;

/** Nonce TTL from Zod defaults. */
export const testNonceTtlMs = cfg.relay.nonce_ttl_ms;

// ---------------------------------------------------------------------------
// Protobuf-envelope wire helpers
//
// After dicode-core#195, the relay protocol is carried in an envelope with a
// single top-level variant key (e.g. {"challenge": {...}}, {"hello": {...}}).
// Tests that build or parse raw WebSocket frames go through these helpers so
// the envelope shape lives in one place.
// ---------------------------------------------------------------------------

/** Parse an outgoing server frame and return its challenge payload, or null. */
export function parseChallenge(data: Buffer | string): { nonce: string } | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const ch = env.challenge as { nonce: string } | undefined;
  return ch ?? null;
}

/** Parse an outgoing server frame and return its welcome payload, or null. */
export function parseWelcome(data: Buffer | string): Record<string, unknown> | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const w = env.welcome as Record<string, unknown> | undefined;
  return w ?? null;
}

/** Parse an outgoing server frame and return its error payload, or null. */
export function parseError(data: Buffer | string): { message: string } | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const e = env.error as { message: string } | undefined;
  return e ?? null;
}

/** Parse an outgoing server frame and return the request payload, or null. */
export function parseRequest(
  data: Buffer | string,
): { id: string; method: string; path: string; body: string } | null {
  const env = JSON.parse(typeof data === "string" ? data : data.toString()) as Record<
    string,
    unknown
  >;
  const r = env.request as { id: string; method: string; path: string; body: string } | undefined;
  return r ?? null;
}

/** Build a client → server hello envelope (fields use snake_case per proto). */
export function helloEnvelope(fields: {
  uuid: string;
  pubkey: string;
  decrypt_pubkey: string;
  sig: string;
  timestamp: number;
}): string {
  return JSON.stringify({ hello: fields });
}

/** Build a client → server response envelope. Headers are wrapped in {values}. */
export function responseEnvelope(resp: {
  id: string;
  status: number;
  headers?: Record<string, string[]>;
  body: string;
}): string {
  const wireHeaders: Record<string, { values: string[] }> = {};
  for (const [k, v] of Object.entries(resp.headers ?? {})) {
    wireHeaders[k] = { values: v };
  }
  return JSON.stringify({
    response: { id: resp.id, status: resp.status, headers: wireHeaders, body: resp.body },
  });
}
