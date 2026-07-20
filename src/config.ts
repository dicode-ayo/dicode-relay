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

// The dedicated daemon control-channel listener. Always TLS (mTLS: client
// certificates are requested and carry the daemon identity). cert_file /
// key_file empty → fall back to server.tls.*; if that is also empty, a
// self-signed dev cert is auto-provisioned (see start.ts).
const MtlsSchema = z.object({
  port: z.number().int().default(5554),
  cert_file: z.string().default(""),
  key_file: z.string().default(""),
});

const ServerSchema = z
  .object({
    port: z.number().int().default(5553),
    // Declares a multi-instance deployment (2+ relay instances behind a load
    // balancer sharing one public identity). When true, the per-cwd
    // auto-generate fallbacks for the broker signing key and the mTLS server
    // cert become a hard startup error: divergent per-instance material would
    // make daemons reject token-delivery signatures (broker_sig) and cert
    // pinning against every instance but the one that minted the key. Operators
    // must instead supply identical shared material to every instance
    // (broker.signing_key_file + server.mtls.cert_file/key_file, or a shared
    // server.tls cert). Default false keeps the single-instance auto-generate
    // convenience.
    multi_instance: z.boolean().default(false),
    // base_url is optional (absent → fall back to http://localhost:<port>
    // via the .transform below), but when explicitly set in YAML it must be a
    // non-empty string. Catches the common footgun of writing
    // `base_url: ${BASE_URL}` in relay.yaml with `BASE_URL` unset: env
    // interpolation collapses to "", and the relay would silently advertise
    // wss://localhost:<port>/u/... in the welcome message and break OAuth
    // callback URLs in production.
    //
    // .nullish() (instead of .optional()) so YAML forms that produce `null`
    // (`base_url:`, `base_url: ~`, `base_url: null`) are also accepted as
    // "absent" — js-yaml parses an empty key value to `null`, not undefined,
    // and .optional() alone would yield a generic "expected string, received
    // null" error rather than treating it as the documented "omit to default".
    // The .transform() collapses null → undefined so the outer .transform
    // keeps working without a second null check.
    base_url: z
      .string()
      .min(
        1,
        "server.base_url must be non-empty — set BASE_URL or remove the key to default to http://localhost:<port>",
      )
      .nullish()
      .transform((v) => v ?? undefined),
    tls: TlsSchema.default(() => TlsSchema.parse({})),
    mtls: MtlsSchema.default(() => MtlsSchema.parse({})),
  })
  .transform((s) => ({
    ...s,
    base_url:
      s.base_url !== undefined && s.base_url !== ""
        ? s.base_url
        : `http://localhost:${String(s.port)}`,
  }));

const StatusSchema = z.object({
  // password is optional (absent → /status returns 404, dashboard is disabled
  // via statusAuth(undefined)), but when explicitly set in YAML it must be a
  // non-empty string. This rejects the footgun of writing
  // `password: ${STATUS_PASSWORD}` with STATUS_PASSWORD unset: env
  // interpolation collapses to "", which the previous start.ts logic mapped
  // back to "no password → no auth" and silently exposed the dashboard.
  // Operators who want to disable the dashboard must omit the key.
  //
  // .nullish() so the common YAML forms `password:` (no value), `password: ~`,
  // and `password: null` — all parsed by js-yaml as `null` — are treated as
  // "absent" rather than producing a generic Zod "expected string, received
  // null" error. The .transform() collapses null → undefined so downstream
  // `statusAuth(statusCfg.password)` keeps receiving `undefined` for "off".
  password: z
    .string()
    .min(
      1,
      "status.password must be non-empty — set STATUS_PASSWORD or remove the key to disable /status (returns 404)",
    )
    .nullish()
    .transform((v) => v ?? undefined),
});

const RelaySchema = z.object({
  // Clock-skew tolerance for the broker /auth request freshness check.
  timestamp_tolerance_s: z.number().int().default(30),
  ping_interval_ms: z.number().int().default(30_000),
  pong_timeout_ms: z.number().int().default(10_000),
  request_timeout_ms: z.number().int().default(30_000),
});

const BrokerSchema = z.object({
  session_ttl_ms: z.number().int().default(300_000),
  signing_key_file: z.string().default(""),
  providers: z.record(z.string(), ProviderSchema).default(() => ({})),
});

export const ConfigSchema = z.object({
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

/**
 * Determine the config file path.
 *
 * Resolution order:
 *   1. Explicit `configPath` argument (highest priority — used by the CLI and
 *      programmatic `startServer({ configPath })` callers).
 *   2. `RELAY_CONFIG` env var.
 *   3. `relay.yaml` in the current working directory.
 *
 * This function does NOT inspect `process.argv` — CLI argument parsing lives
 * in the bin entrypoint (`src/index.ts`) so the library is pure with respect
 * to argv. Library callers that need a different path pass it explicitly.
 */
function resolveConfigPath(env: NodeJS.ProcessEnv, configPath?: string): string {
  if (configPath !== undefined && configPath !== "") return configPath;
  return env.RELAY_CONFIG ?? "relay.yaml";
}

/**
 * Load and validate the relay config.
 * Throws if the config file does not exist.
 *
 * @param env         env source for `${VAR}` interpolation (default: process.env)
 * @param configPath  optional explicit path to the YAML file (overrides
 *                    RELAY_CONFIG env / default `relay.yaml`)
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env, configPath?: string): RelayConfig {
  const path = resolveConfigPath(env, configPath);

  if (!existsSync(path)) {
    throw new Error(
      `Config file not found: ${path}\n` +
        `Copy relay.yaml.example to relay.yaml and configure it for your environment.`,
    );
  }

  const raw = readFileSync(path, "utf8");
  const parsed = yamlLoad(raw) as Record<string, unknown> | null;
  const resolved = resolveDeep(parsed ?? {}, env);
  return ConfigSchema.parse(resolved);
}
