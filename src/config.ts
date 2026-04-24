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
  return value.replace(/\$\{([^}]*)\}/g, (_match, name: string) => {
    if (name === "") {
      console.warn(`config: empty \${} interpolation — likely a typo in relay.yaml`);
      return "";
    }
    const resolved = env[name];
    if (resolved === undefined) {
      // Surface unresolved env refs so operators can spot typos or missing
      // secrets. Collapsing to "" is fine for provider credentials (empty
      // client_id silently disables the provider), but is a footgun for
      // fields like broker.signing_key_file where "" triggers key auto-
      // generation and rotates the broker pubkey. Always warn; callers
      // can still opt into empty-as-disabled by using `default:` in Zod.
      console.warn(
        `config: \${${name}} is unset — value resolved to empty string. ` +
          `If this is intentional (e.g. disabling a provider), ignore; ` +
          `otherwise set the env var or use a literal value.`,
      );
      return "";
    }
    return resolved;
  });
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

const ServerSchema = z
  .object({
    port: z.number().int().default(5553),
    base_url: z.string().default(""),
    tls: TlsSchema.default(() => TlsSchema.parse({})),
  })
  .transform((s) => ({
    ...s,
    base_url: s.base_url !== "" ? s.base_url : `http://localhost:${String(s.port)}`,
  }));

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

/** Parse an empty object through the schema to get all Zod defaults.
 *  Use in tests instead of duplicating default values. */
export function defaultConfig(): RelayConfig {
  return ConfigSchema.parse({});
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/** Determine the config file path from CLI args or env. */
function resolveConfigPath(env: NodeJS.ProcessEnv): string {
  const args = process.argv;
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === "--config") {
      const next = args[i + 1];
      if (next !== undefined) return next;
    }
  }
  return env.RELAY_CONFIG ?? "relay.yaml";
}

/**
 * Load and validate the relay config.
 * Throws if the config file does not exist.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const configPath = resolveConfigPath(env);

  if (!existsSync(configPath)) {
    throw new Error(
      `Config file not found: ${configPath}\n` +
        `Copy relay.yaml.example to relay.yaml and configure it for your environment.`,
    );
  }

  const raw = readFileSync(configPath, "utf8");
  const parsed = yamlLoad(raw) as Record<string, unknown> | null;
  const resolved = resolveDeep(parsed ?? {}, env);
  return ConfigSchema.parse(resolved);
}
