/**
 * Relay configuration loader.
 *
 * Resolution order:
 *   1. relay.yaml (or path from --config CLI arg / RELAY_CONFIG env)
 *   2. Fallback: construct config from process.env using legacy env var names
 *
 * String values in the YAML support ${ENV_VAR} interpolation.
 */

import { existsSync, readFileSync } from "node:fs";
import { load as yamlLoad } from "js-yaml";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Env variable resolution
// ---------------------------------------------------------------------------

function resolveEnvVars(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, name: string) => env[name] ?? "");
}

/** Recursively walk a parsed YAML value and resolve ${...} in all strings. */
function resolveDeep(obj: unknown, env: NodeJS.ProcessEnv): unknown {
  if (typeof obj === "string") return resolveEnvVars(obj, env);
  if (Array.isArray(obj)) return obj.map((v) => resolveDeep(v, env));
  if (obj !== null && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = resolveDeep(v, env);
    }
    return out;
  }
  return obj; // numbers, booleans, null — pass through
}

// ---------------------------------------------------------------------------
// Zod schema
// ---------------------------------------------------------------------------

const ProviderSchema = z.object({
  client_id: z.string().default(""),
  client_secret: z.string().optional(),
  pkce: z.boolean().default(true),
  scopes: z.array(z.string()).default([]),
});

const TlsSchema = z.object({
  cert_file: z.string().default(""),
  key_file: z.string().default(""),
});

const ServerSchema = z.object({
  port: z.number().int().default(5553),
  base_url: z.string().default(""),
  tls: TlsSchema.default(() => TlsSchema.parse({})),
});

const StatusSchema = z.object({
  password: z.string().default(""),
});

const RelaySchema = z.object({
  timestamp_tolerance_s: z.number().int().default(30),
  ping_interval_ms: z.number().int().default(30_000),
  pong_timeout_ms: z.number().int().default(10_000),
  request_timeout_ms: z.number().int().default(30_000),
  nonce_ttl_ms: z.number().int().default(60_000),
});

const BrokerSchema = z.object({
  session_ttl_ms: z.number().int().default(300_000),
  signing_key_file: z.string().default(""),
  providers: z.record(z.string(), ProviderSchema).default(() => ({})),
});

const ConfigSchema = z.object({
  server: ServerSchema.default(() => ServerSchema.parse({})),
  status: StatusSchema.default(() => StatusSchema.parse({})),
  relay: RelaySchema.default(() => RelaySchema.parse({})),
  broker: BrokerSchema.default(() => BrokerSchema.parse({})),
});

export type RelayConfig = z.infer<typeof ConfigSchema>;
export type ProviderEntry = z.infer<typeof ProviderSchema>;

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/** Determine the config file path from CLI args or env. */
function resolveConfigPath(): string {
  const args = process.argv;
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === "--config") {
      const next = args[i + 1];
      if (next !== undefined) return next;
    }
  }
  return process.env.RELAY_CONFIG ?? "relay.yaml";
}

/**
 * Load and validate the relay config. If the YAML file doesn't exist,
 * falls back to a backward-compatible config built from process.env.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const configPath = resolveConfigPath();

  if (existsSync(configPath)) {
    const raw = readFileSync(configPath, "utf8");
    const parsed = yamlLoad(raw) as Record<string, unknown> | null;
    const resolved = resolveDeep(parsed ?? {}, env);
    const config = ConfigSchema.parse(resolved);
    // Derive base_url from port if not set
    if (config.server.base_url === "") {
      config.server.base_url = `http://localhost:${String(config.server.port)}`;
    }
    return config;
  }

  // Fallback: build config from legacy env vars
  return buildLegacyConfig(env);
}

// ---------------------------------------------------------------------------
// Legacy env var fallback
// ---------------------------------------------------------------------------

interface LegacyProvider {
  clientIdEnv: string;
  secretEnv: string | null;
  pkce: boolean;
  scopes: string[];
}

const LEGACY_PROVIDERS: Record<string, LegacyProvider> = {
  github:     { clientIdEnv: "GITHUB_CLIENT_ID",     secretEnv: "GITHUB_CLIENT_SECRET",     pkce: true,  scopes: ["user", "repo"] },
  slack:      { clientIdEnv: "SLACK_CLIENT_ID",       secretEnv: null,                        pkce: true,  scopes: ["channels:read"] },
  google:     { clientIdEnv: "GOOGLE_CLIENT_ID",      secretEnv: "GOOGLE_CLIENT_SECRET",      pkce: true,  scopes: ["https://www.googleapis.com/auth/userinfo.email"] },
  spotify:    { clientIdEnv: "SPOTIFY_CLIENT_ID",     secretEnv: null,                        pkce: true,  scopes: ["user-read-private", "user-read-email"] },
  linear:     { clientIdEnv: "LINEAR_CLIENT_ID",      secretEnv: null,                        pkce: true,  scopes: ["read"] },
  discord:    { clientIdEnv: "DISCORD_CLIENT_ID",     secretEnv: null,                        pkce: true,  scopes: ["identify", "email"] },
  gitlab:     { clientIdEnv: "GITLAB_CLIENT_ID",      secretEnv: "GITLAB_CLIENT_SECRET",      pkce: true,  scopes: ["read_user", "read_api"] },
  airtable:   { clientIdEnv: "AIRTABLE_CLIENT_ID",    secretEnv: "AIRTABLE_CLIENT_SECRET",    pkce: true,  scopes: ["data.records:read"] },
  notion:     { clientIdEnv: "NOTION_CLIENT_ID",      secretEnv: "NOTION_CLIENT_SECRET",      pkce: false, scopes: [] },
  confluence: { clientIdEnv: "CONFLUENCE_CLIENT_ID",   secretEnv: null,                        pkce: true,  scopes: ["read:me", "read:confluence-content.all", "offline_access"] },
  salesforce: { clientIdEnv: "SALESFORCE_CLIENT_ID",   secretEnv: null,                        pkce: true,  scopes: ["api", "refresh_token"] },
  stripe:     { clientIdEnv: "STRIPE_CLIENT_ID",       secretEnv: "STRIPE_CLIENT_SECRET",      pkce: false, scopes: ["read_write"] },
  office365:  { clientIdEnv: "OFFICE365_CLIENT_ID",    secretEnv: "OFFICE365_CLIENT_SECRET",   pkce: true,  scopes: ["offline_access", "User.Read", "Mail.Read"] },
  azure:      { clientIdEnv: "AZURE_CLIENT_ID",        secretEnv: "AZURE_CLIENT_SECRET",       pkce: true,  scopes: ["openid", "profile", "email", "offline_access"] },
};

function buildLegacyConfig(env: NodeJS.ProcessEnv): RelayConfig {
  const port = parseInt(env.PORT ?? "5553", 10);
  const providers: Record<string, ProviderEntry> = {};
  for (const [key, lp] of Object.entries(LEGACY_PROVIDERS)) {
    providers[key] = {
      client_id: env[lp.clientIdEnv] ?? "",
      ...(lp.secretEnv !== null ? { client_secret: env[lp.secretEnv] ?? "" } : {}),
      pkce: lp.pkce,
      scopes: lp.scopes,
    };
  }
  return {
    server: {
      port,
      base_url: env.BASE_URL ?? `http://localhost:${String(port)}`,
      tls: {
        cert_file: env.TLS_CERT_FILE ?? "",
        key_file: env.TLS_KEY_FILE ?? "",
      },
    },
    status: { password: env.STATUS_PASSWORD ?? "" },
    relay: {
      timestamp_tolerance_s: 30,
      ping_interval_ms: 30_000,
      pong_timeout_ms: 10_000,
      request_timeout_ms: 30_000,
      nonce_ttl_ms: 60_000,
    },
    broker: {
      session_ttl_ms: 300_000,
      signing_key_file: env.BROKER_SIGNING_KEY_FILE ?? "",
      providers,
    },
  };
}
