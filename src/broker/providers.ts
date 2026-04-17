/**
 * Provider configuration — built from the relay.yaml config at startup.
 *
 * No providers are hardcoded here. The config file defines the full list;
 * users add new providers by adding YAML entries, no code change needed.
 */

import type { RelayConfig } from "../config.js";

/** Runtime provider config with resolved (non-env-ref) values. */
export interface ProviderConfig {
  /** Grant's provider key — same as the YAML key (e.g. "github", "slack") */
  grantKey: string;
  /** Resolved client ID (empty → provider skipped) */
  clientId: string;
  /** Resolved client secret (undefined for PKCE-only providers) */
  clientSecret?: string;
  /** Whether to enable PKCE */
  pkce: boolean;
  /** Default scopes */
  scopes: string[];
}

/**
 * Build the enabled-provider map from the parsed config.
 * Providers whose client_id is empty after env resolution are silently
 * skipped — same behavior as the legacy env-var-based setup.
 */
export function buildProviderMap(config: RelayConfig): ReadonlyMap<string, ProviderConfig> {
  const map = new Map<string, ProviderConfig>();
  for (const [key, entry] of Object.entries(config.broker.providers)) {
    if (entry.client_id === "") continue; // not configured
    const pc: ProviderConfig = {
      grantKey: key,
      clientId: entry.client_id,
      pkce: entry.pkce,
      scopes: entry.scopes,
    };
    if (entry.client_secret !== undefined && entry.client_secret !== "") {
      pc.clientSecret = entry.client_secret;
    }
    map.set(key, pc);
  }
  return map;
}
