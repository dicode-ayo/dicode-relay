# dicode-relay — Agent Task

## What you are building

A production-ready TypeScript/Node.js service that combines two tightly coupled
functions in one process:

1. **Relay server** — a WebSocket tunnel that lets local dicode daemons (running
   behind NAT on developer laptops) receive inbound HTTP requests without a
   public port or ngrok. The daemon connects outbound over WSS; the relay server
   forwards arriving HTTP requests as WebSocket messages and sends responses back.

2. **OAuth broker** — holds dicode's registered `client_id`/`client_secret` for
   each OAuth provider (GitHub, Slack, Google, etc.). Executes the full
   authorization-code flow on behalf of users, then delivers the final access
   token back to the daemon over the relay WebSocket, **encrypted with the
   daemon's P-256 public key**. Users never register their own OAuth apps.

The relay client (Go binary, `pkg/relay/client.go` in dicode-core) connects to
this service. The protocol it speaks is defined in PR #79 of dicode-core and is
reproduced in full in the protocol spec below — do not deviate from it.

---

## Design document

Read `/home/dr14/dicode/docs/design/oauth-broker.md` in full before writing
any code. It contains:
- Architecture diagram
- Step-by-step flow with sequence diagram
- Full security design (ECDSA sig verification, ECIES token encryption, PKCE binding, replay prevention)
- Exact protocol message schemas
- Threat model

---

## Technology choices

| Concern | Choice | Reason |
| --- | --- | --- |
| Language | **TypeScript 5**, strict mode | Type safety across the protocol boundary |
| Runtime | **Node.js 22 LTS** | `node:crypto` has native ECDH/AES-GCM/HKDF; no extra crypto dep |
| WebSocket | **`ws` 8.x** | Battle-tested, no unnecessary abstraction |
| HTTP framework | **Express 5** | Grant requires Express-compatible middleware |
| OAuth middleware | **`grant` 5.x** | 200+ providers, handles PKCE, `state`, code exchange |
| Test runner | **Vitest** | Fast, native ESM, inline types, good coverage reporting |
| Linter | **ESLint v9** (flat config) | |
| Formatter | **Prettier 3** | |
| Build | **`tsc`** (no bundler) | Output to `dist/`, Node.js resolves directly |

Do **not** add:
- `axios` / `node-fetch` — use native `fetch` (Node.js 22 built-in)
- `dotenv` in production — use `process.env` directly; `.env` is for local dev only via `--env-file`
- `lodash` or any utility belt — standard library only
- `jsonwebtoken` — use `node:crypto` directly

---

## Repository layout

```
dicode-relay/
├── src/
│   ├── index.ts              # entry: creates RelayServer + BrokerRouter, starts HTTPS
│   ├── relay/
│   │   ├── server.ts         # RelayServer class: WS handshake, client registry, forward()
│   │   ├── protocol.ts       # Zod schemas + TypeScript types for all WS message types
│   │   └── nonces.ts         # NonceStore: Set with per-entry 60 s TTL, O(1) lookup
│   └── broker/
│       ├── router.ts         # Express Router: GET /auth/:provider, GET /callback/:provider
│       ├── grant.ts          # buildGrantConfig(providers, baseUrl) → Grant middleware
│       ├── providers.ts      # PROVIDER_CONFIGS: per-provider env var names + Grant options
│       ├── sessions.ts       # SessionStore: Map<sessionId, Session> with 5 min TTL
│       └── crypto.ts         # verifyECDSA(), eciesEncrypt(), buildSignedPayload()
├── tests/
│   ├── relay/
│   │   ├── handshake.test.ts
│   │   └── forward.test.ts
│   └── broker/
│       ├── auth.test.ts
│       └── crypto.test.ts
├── docs/
│   └── providers.md          # table of supported providers and required env vars
├── tsconfig.json
├── tsconfig.build.json
├── eslint.config.ts
├── prettier.config.ts
├── vitest.config.ts
├── package.json
├── Dockerfile
├── .env.example
└── README.md
```

---

## TypeScript config

**`tsconfig.json`** (used by IDE + tests):
```json
{
  "compilerOptions": {
    "target": "ES2023",
    "module": "Node16",
    "moduleResolution": "Node16",
    "lib": ["ES2023"],
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "esModuleInterop": true,
    "skipLibCheck": false
  },
  "include": ["src", "tests"]
}
```

**`tsconfig.build.json`** (used by `tsc --project tsconfig.build.json` in CI/Docker):
```json
{
  "extends": "./tsconfig.json",
  "include": ["src"],
  "exclude": ["tests"]
}
```

---

## ESLint config (flat, ESLint v9)

**`eslint.config.ts`**:
```ts
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: { project: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  { ignores: ["dist/", "coverage/"] },
);
```

---

## Prettier config

**`prettier.config.ts`**:
```ts
import type { Config } from "prettier";

const config: Config = {
  semi: true,
  singleQuote: false,
  trailingComma: "all",
  printWidth: 100,
  tabWidth: 2,
};

export default config;
```

---

## package.json scripts

```json
{
  "scripts": {
    "build":        "tsc --project tsconfig.build.json",
    "start":        "node dist/index.js",
    "dev":          "tsx watch src/index.ts",
    "test":         "vitest run",
    "test:watch":   "vitest",
    "test:coverage":"vitest run --coverage",
    "lint":         "eslint src tests",
    "lint:fix":     "eslint src tests --fix",
    "format":       "prettier --write src tests",
    "format:check": "prettier --check src tests",
    "typecheck":    "tsc --noEmit"
  }
}
```

CI runs: `npm run typecheck && npm run lint && npm run format:check && npm run test`

---

## Protocol specification (from PR #79 — implement exactly)

All WebSocket messages are JSON text frames.

### Relay handshake

```
Server → Client:
  { "type": "challenge", "nonce": "<64 lowercase hex chars>" }

Client → Server:
  {
    "type":      "hello",
    "uuid":      "<64 lowercase hex>",   // hex(sha256(uncompressed_pubkey))
    "pubkey":    "<base64 std>",         // 65 bytes: 0x04 || X || Y
    "sig":       "<base64 std>",         // ECDSA P-256 ASN.1 DER over sha256(nonce_bytes || timestamp_be_uint64)
    "timestamp": <unix seconds integer>
  }

Server → Client (success):
  { "type": "welcome", "url": "wss://relay.dicode.app/u/<uuid>/hooks/" }

Server → Client (failure):
  { "type": "error", "message": "<reason>" }
```

**Server verification steps (implement all, reject on any failure):**
1. Decode `pubkey` from base64 → must be exactly 65 bytes starting with `0x04`
2. Compute `hex(sha256(pubkeyBytes))` → must equal `uuid`
3. Verify `timestamp` is within ±30 seconds of `Date.now() / 1000`
4. Verify `nonce` has not been seen in the last 60 seconds (NonceStore)
5. Verify ECDSA P-256 signature: message = `sha256(nonceBytes || timestampBigEndianUint64)`
6. Store `{ uuid → ConnectedClient }` in registry
7. Start ping interval (30 s); close connection if pong not received within 10 s

### Webhook forwarding

```
Server → Client (inbound request):
  {
    "type":    "request",
    "id":      "<uuidv4>",
    "method":  "POST",
    "path":    "/hooks/some-task",
    "headers": { "Content-Type": ["application/json"] },
    "body":    "<base64 encoded bytes>"
  }

Client → Server (response):
  {
    "type":    "response",
    "id":      "<same uuidv4>",
    "status":  200,
    "headers": { "Content-Type": ["application/json"] },
    "body":    "<base64 encoded bytes>"
  }
```

The relay server holds pending requests in a `Map<id, { resolve, reject, timer }>`
with a 30 s timeout. On timeout, respond 504 to the original HTTP caller.

### OAuth token delivery message

When the broker completes a token exchange, the relay server calls
`relayServer.forward(uuid, payload)` which sends a `request` message to the
daemon at path `/hooks/oauth-complete` with the ECIES-encrypted payload as the
body. The daemon's existing webhook handler picks it up as a normal webhook.

---

## Security implementation

### ECDSA signature verification (`src/broker/crypto.ts`)

```ts
import { createVerify, createHash } from "node:crypto";

export function buildSignedPayload(
  sessionId: string,    // UUID v4, raw bytes
  pkceChallenge: string,// base64url string, decoded to bytes
  relayUuid: string,    // 64 hex chars, decoded to 32 bytes
  provider: string,     // UTF-8
  timestamp: number,    // Unix seconds
): Buffer {
  const ts = Buffer.allocUnsafe(8);
  ts.writeBigUInt64BE(BigInt(timestamp));
  return createHash("sha256")
    .update(Buffer.from(sessionId.replace(/-/g, ""), "hex"))
    .update(Buffer.from(pkceChallenge, "base64url"))
    .update(Buffer.from(relayUuid, "hex"))
    .update(Buffer.from(provider, "utf8"))
    .update(ts)
    .digest();
}

export function verifyECDSA(
  pubkeyBytes: Buffer,   // 65-byte uncompressed P-256
  payload: Buffer,
  sigDerBase64: string,
): boolean {
  const verify = createVerify("SHA256");
  verify.update(payload);
  return verify.verify(
    { key: pubkeyBytes, format: "der", type: "spki" },  // Node.js accepts raw key
    Buffer.from(sigDerBase64, "base64"),
    "der",
  );
}
```

### ECIES token encryption (`src/broker/crypto.ts`)

```ts
import { createECDH, createSecretKey, randomBytes } from "node:crypto";
import { hkdf } from "node:crypto";
import { promisify } from "node:util";
import { createCipheriv } from "node:crypto";

const hkdfAsync = promisify(hkdf);

export interface EciesPayload {
  ephemeralPubkey: string;  // base64, 65-byte uncompressed P-256
  ciphertext:      string;  // base64
  nonce:           string;  // base64, 12 bytes
}

export async function eciesEncrypt(
  daemonPubkeyBytes: Buffer,  // 65-byte uncompressed P-256
  sessionId: string,           // used as HKDF salt
  plaintext: Buffer,
): Promise<EciesPayload> {
  const eph = createECDH("prime256v1");
  eph.generateKeys();

  // ECDH: ephemeral private × daemon public
  const sharedSecret = eph.computeSecret(daemonPubkeyBytes);

  // HKDF-SHA256 → 32-byte AES key
  const encKey = Buffer.from(
    await hkdfAsync("sha256", sharedSecret, Buffer.from(sessionId), "dicode-oauth-token", 32),
  );

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  return {
    ephemeralPubkey: eph.getPublicKey("base64"),
    ciphertext:      ct.toString("base64"),
    nonce:           iv.toString("base64"),
  };
}
```

> The auth tag (16 bytes) is appended to the ciphertext. The Go daemon must
> split the last 16 bytes off the ciphertext before passing to `aesGCM.Open`.
> Document this in `docs/providers.md` and a comment in the source.

---

## Grant provider configuration

Each provider entry in `src/broker/providers.ts` must specify:

```ts
interface ProviderConfig {
  grantKey:    string;           // Grant's provider key (e.g. "github", "google")
  clientIdEnv: string;           // env var holding client_id (e.g. "GITHUB_CLIENT_ID")
  secretEnv:   string | null;    // env var holding client_secret; null = PKCE-only
  pkce:        boolean;
  scopes:      string[];         // default scopes; task.ts can override via ?scope=
}
```

Providers to support on day one (from `tasks/auth/taskset.yaml` in dicode-core):

| Provider key | PKCE | Secret required | Default scopes |
| --- | --- | --- | --- |
| `github` | yes | yes | `user repo` |
| `slack` | yes | no | `channels:read` |
| `google` | yes | yes | `https://www.googleapis.com/auth/userinfo.email` |
| `spotify` | yes | no | `user-read-private user-read-email` |
| `linear` | yes | no | `read` |
| `discord` | yes | no | `identify email` |
| `gitlab` | yes | yes | `read_user read_api` |
| `airtable` | yes | yes | `data.records:read` |
| `notion` | no | yes | `` (empty — Notion ignores scope) |
| `confluence` | yes | no | `read:me read:confluence-content.all offline_access` |
| `salesforce` | yes | no | `api refresh_token` |
| `stripe` | no | yes | `read_write` |
| `office365` | yes | yes | `offline_access User.Read Mail.Read` |
| `azure` | yes | yes | `openid profile email offline_access` |

Grant's `dynamic: ["scope", "state"]` must be enabled for all providers so that
per-request scope overrides from `task.ts` are respected.

---

## Tests

Write tests using **Vitest**. Do not mock the crypto functions — use real
key generation and verification. Do not mock the WebSocket protocol — use an
in-process `RelayServer` instance with a real `ws.WebSocket` client connecting
to a random port.

### Required test cases

**`tests/relay/handshake.test.ts`**
- Valid handshake: client connects, challenge-response succeeds, `welcome` received
- Wrong pubkey: `uuid` does not match `sha256(pubkey)` → `error` message, connection closed
- Stale timestamp (>30 s old) → `error`, connection closed
- Replayed nonce (send same hello twice) → second attempt rejected
- Connection cleanup: client disconnects, registry entry removed

**`tests/relay/forward.test.ts`**
- `relayServer.forward(uuid, path, body)` sends `request` message to correct WS
- Client sends `response`, `forward()` resolves with response body
- Timeout (no response within 30 s) → `forward()` rejects
- Forward to unknown UUID → throws `ClientNotConnectedError`

**`tests/broker/auth.test.ts`**
- Valid `GET /auth/github` request with correct sig → session created, redirect to Grant
- Missing `relay_uuid` → 400
- UUID not in relay registry → 403
- Bad ECDSA signature → 403
- Stale timestamp → 403

**`tests/broker/crypto.test.ts`**
- `eciesEncrypt` + daemon-side decrypt round-trip (pure Node.js)
- `verifyECDSA` returns true for valid sig, false for tampered payload
- `buildSignedPayload` is deterministic for same inputs

### Coverage target

90% line coverage. Run `npm run test:coverage` and fail CI if below threshold.
Configure in `vitest.config.ts`:
```ts
coverage: { provider: "v8", thresholds: { lines: 90, functions: 90 } }
```

---

## Dockerfile

Multi-stage, non-root user, no dev dependencies in final image:

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig*.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime
RUN addgroup -S dicode && adduser -S dicode -G dicode
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
USER dicode
EXPOSE 8080
CMD ["node", "dist/index.js"]
```

---

## Environment variables

Document all of these in `.env.example` with comments:

```sh
# Service
PORT=8080
BASE_URL=https://relay.dicode.app        # used in welcome message URL

# TLS (optional — skip if terminated by Cloudflare/nginx)
TLS_CERT_FILE=
TLS_KEY_FILE=

# Provider credentials — set only the providers you have registered
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
SLACK_CLIENT_ID=
# SLACK_CLIENT_SECRET not needed (PKCE-only)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
SPOTIFY_CLIENT_ID=
# SPOTIFY_CLIENT_SECRET not needed (PKCE-only)
LINEAR_CLIENT_ID=
# LINEAR_CLIENT_SECRET not needed (PKCE-only)
DISCORD_CLIENT_ID=
# DISCORD_CLIENT_SECRET not needed (PKCE-only)
GITLAB_CLIENT_ID=
GITLAB_CLIENT_SECRET=
AIRTABLE_CLIENT_ID=
AIRTABLE_CLIENT_SECRET=
NOTION_CLIENT_ID=
NOTION_CLIENT_SECRET=
CONFLUENCE_CLIENT_ID=
# CONFLUENCE_CLIENT_SECRET not needed (PKCE-only)
SALESFORCE_CLIENT_ID=
# SALESFORCE_CLIENT_SECRET not needed (PKCE-only)
STRIPE_CLIENT_ID=
STRIPE_CLIENT_SECRET=
OFFICE365_CLIENT_ID=
OFFICE365_CLIENT_SECRET=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
```

---

## README requirements

The README must include:

1. **One-paragraph summary** of what this service does and why it exists
2. **Architecture diagram** (copy the ASCII art from the design doc)
3. **Quick start** (clone → set env vars → `npm run dev`)
4. **Environment variable reference** (same as `.env.example` but with descriptions)
5. **Relay protocol reference** (the handshake and forwarding message schemas)
6. **Security model** (3–5 bullet points linking to design doc for details)
7. **Deployment** section (Docker, Cloudflare, self-host)
8. **Contributing** (run tests, lint, format before PR)

---

## docs/providers.md requirements

A table of every supported provider with:
- Provider name
- Required env vars
- Whether PKCE is used
- Whether `client_secret` is required
- Default scopes
- Link to provider's OAuth app registration page
- Note on any provider quirks (e.g. Notion uses HTTP Basic auth, Stripe returns `stripe_user_id`)

Also document the ECIES payload format and the AES-GCM auth tag convention
(auth tag appended to ciphertext, Go daemon must split it).

---

## CI (GitHub Actions)

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: npm }
      - run: npm ci
      - run: npm run typecheck
      - run: npm run lint
      - run: npm run format:check
      - run: npm run test:coverage
      - run: npm run build
```

---

## Order of implementation

1. **`src/relay/protocol.ts`** — Zod schemas and TypeScript types for all message
   types. This is the single source of truth for the protocol. Write it first,
   reference it everywhere.

2. **`src/relay/nonces.ts`** — NonceStore class. Simple, no dependencies.

3. **`src/relay/server.ts`** — RelayServer class. Depends on protocol + nonces.

4. **Tests for relay** — `tests/relay/handshake.test.ts` and `forward.test.ts`.
   Make these pass before touching the broker.

5. **`src/broker/crypto.ts`** — ECDSA verify + ECIES encrypt. Pure crypto, no
   HTTP, testable in isolation.

6. **Tests for crypto** — `tests/broker/crypto.test.ts`. Verify round-trip
   before wiring into the router.

7. **`src/broker/sessions.ts`** — SessionStore.

8. **`src/broker/providers.ts`** — static provider config map.

9. **`src/broker/grant.ts`** — Grant middleware factory.

10. **`src/broker/router.ts`** — Express router wiring it all together.

11. **Tests for broker** — `tests/broker/auth.test.ts`.

12. **`src/index.ts`** — entry point, start server.

13. **`Dockerfile`**, **`.env.example`**, **`README.md`**, **`docs/providers.md`**.

14. **`.github/workflows/ci.yml`**.

---

## What NOT to do

- Do not use `any` — the linter will catch this, but also never cast to `any`
  to silence a type error; fix the type instead
- Do not store tokens in memory beyond the delivery window — once forwarded,
  delete the session immediately
- Do not log token values, access tokens, or client secrets — mask them in
  any debug output
- Do not implement `GET /pubkey/:uuid` as a public HTTP endpoint — the pubkey
  lookup is done in-process via the relay client registry
- Do not add a database — all state is ephemeral in-memory with TTLs
- Do not use `express-session` for broker sessions — use the custom `SessionStore`
  class (Map + TTL) defined in `src/broker/sessions.ts`
- Do not implement refresh token logic — the daemon handles refresh via the
  existing `flow.ts`; the broker only delivers the initial token exchange result
