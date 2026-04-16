/**
 * Grant middleware factory.
 *
 * Builds a Grant configuration object from the config-derived provider map
 * (values already resolved from ${ENV_VAR}) and returns a configured
 * Grant Express middleware instance.
 */

import { createRequire } from "node:module";
import type { GrantConfig, GrantProvider, ExpressMiddleware, GrantInstance } from "grant";
import type { ProviderConfig } from "./providers.js";

// Grant uses CommonJS exports. Import via createRequire for ESM compatibility.
const require = createRequire(import.meta.url);

const grantLib = require("grant") as {
  express: (config: GrantConfig) => ExpressMiddleware & GrantInstance;
};

/**
 * Build and return a configured Grant middleware.
 *
 * @param providers  The enabled provider map (already resolved, not env var names)
 * @param baseUrl    Public base URL of this service (e.g. "https://relay.dicode.app")
 */
export function buildGrantMiddleware(
  providers: ReadonlyMap<string, ProviderConfig>,
  baseUrl: string,
): ExpressMiddleware & GrantInstance {
  const defaults: GrantProvider = {
    origin: baseUrl,
    transport: "querystring",
    state: true,
  };

  const config: GrantConfig = { defaults };

  for (const [, pc] of providers) {
    const entry: GrantProvider = {
      client_id: pc.clientId,
      scope: pc.scopes,
      pkce: pc.pkce,
      dynamic: ["scope", "state"],
      callback: `/callback/${pc.grantKey}`,
    };
    if (pc.clientSecret !== undefined) {
      entry.client_secret = pc.clientSecret;
    }
    config[pc.grantKey] = entry;
  }

  return grantLib.express(config);
}
