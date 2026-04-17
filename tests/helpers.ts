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
