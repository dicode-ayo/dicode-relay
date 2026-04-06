/**
 * Grant middleware factory.
 *
 * Builds a Grant configuration object from the enabled providers
 * (those with client_id set in the environment) and returns a configured
 * Grant Express middleware instance.
 */

import { createRequire } from "node:module";
import type { GrantConfig, GrantProvider, ExpressMiddleware, GrantInstance } from "grant";
import type { PROVIDER_CONFIGS } from "./providers.js";

type ProviderConfigMap = typeof PROVIDER_CONFIGS;

// Grant uses CommonJS exports. Import via createRequire for ESM compatibility.
const require = createRequire(import.meta.url);

const grantLib = require("grant") as {
  express: (config: GrantConfig) => ExpressMiddleware & GrantInstance;
};

/**
 * Build and return a configured Grant middleware.
 *
 * @param providers  The PROVIDER_CONFIGS map (passed in for testability)
 * @param baseUrl    Public base URL of this service (e.g. "https://relay.dicode.app")
 * @param env        Environment variables source (defaults to process.env)
 */
export function buildGrantMiddleware(
  providers: ProviderConfigMap,
  baseUrl: string,
  env: NodeJS.ProcessEnv = process.env,
): ExpressMiddleware & GrantInstance {
  const defaults: GrantProvider = {
    origin: baseUrl,
    transport: "querystring",
    state: true,
  };

  const config: GrantConfig = { defaults };

  for (const [, providerCfg] of providers) {
    const clientId = env[providerCfg.clientIdEnv];
    if (clientId === undefined || clientId === "") {
      // Provider not configured in this environment — skip it
      continue;
    }

    const entry: GrantProvider = {
      client_id: clientId,
      scope: providerCfg.scopes,
      pkce: providerCfg.pkce,
      // Allow task.ts to override scope and state per-request
      dynamic: ["scope", "state"],
      callback: `/callback/${providerCfg.grantKey}`,
    };

    if (providerCfg.secretEnv !== null) {
      const secret = env[providerCfg.secretEnv];
      if (secret !== undefined && secret !== "") {
        entry.client_secret = secret;
      }
    }

    config[providerCfg.grantKey] = entry;
  }

  return grantLib.express(config);
}
