# dicode-relay

A production-ready TypeScript/Node.js service that combines an OAuth broker and a WebSocket relay tunnel in a single process. It lets local dicode daemons (running behind NAT on developer laptops) receive OAuth callbacks and inbound webhooks without a public port, ngrok, or per-user OAuth app registration — the broker holds dicode's shared `client_id`/`client_secret` for each provider, executes the full authorization-code flow, and delivers the encrypted access token directly to the daemon over the relay tunnel.

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│  User's machine                                              │
│                                                              │
│  ┌──────────────────┐   WSS over mTLS (persistent)          │
│  │  dicode daemon   │◄──────────────────────────────────┐   │
│  │                  │                                   │   │
│  │  relay client    │   /hooks/oauth-complete delivery  │   │
│  │  (Deno task)     │◄── forwarded over WS ─────────────┤   │
│  │                  │                                   │   │
│  │  OAuth task.ts   │                                   │   │
│  └────────┬─────────┘                                   │   │
│           │ open browser                                │   │
└───────────┼─────────────────────────────────────────────┼───┘
            │                                             │
            ▼                             ┌───────────────┴──────────────┐
   ┌──────────────────────────────────┐   │  dicode-relay (Node.js)      │
   │  Browser                         │   │                              │
   │                                  │   │  ┌────────────────────────┐  │
   │  GET /auth/github                │──►│  │  Relay Server (ws)     │  │
   │    ?session=...                  │   │  │  - mTLS client certs   │  │
   │    &relay_uuid=...               │   │  │  - client registry     │  │
   │    &sig=...                      │   │  │  - request forwarding  │  │
   │                                  │   │  └────────────────────────┘  │
   │  ← redirect to GitHub            │   │                              │
   │  ← redirect back to /callback    │   │  ┌────────────────────────┐  │
   │                                  │   │  │  OAuth Broker (Grant)  │  │
   │  ← "Authorization complete"      │   │  │  - holds client creds  │  │
   └──────────────────────────────────┘   │  │  - code exchange       │  │
                                          │  │  - token encryption    │  │
                                          │  │  - delivers via relay  │  │
               ┌──────────────────────┐  │  └────────────────────────┘  │
               │  GitHub / Slack / …  │◄─┤                              │
               │  (provider OAuth)    │  │  public HTTPS + mTLS WSS     │
               └──────────────────────┘  └──────────────────────────────┘
```

---

## Install & run

The fastest path — no clone, no Node setup beyond a recent Node:

```sh
npx dicode-relay
# or install globally
npm install -g dicode-relay && dicode-relay
```

Configuration is read from `relay.yaml` (or `--config` / `$RELAY_CONFIG`). With
no file, the process falls back to `process.env`, so for a quick local run
export `BASE_URL` + at least one provider's `CLIENT_ID` / `CLIENT_SECRET` and
go.

### From source

```sh
git clone https://github.com/dicode-ayo/dicode-relay
cd dicode-relay
cp .env.example .env
# Edit .env: set BASE_URL and at least one provider's CLIENT_ID/SECRET
npm install
npm run dev
```

### Docker

```sh
docker pull dicodeayo/dicode-relay
docker run -p 5553:5553 -p 5554:5554 --env-file .env dicodeayo/dicode-relay
```

Also mirrored at `ghcr.io/dicode-ayo/dicode-relay` if you prefer to pull from GitHub's registry.

---

## Environment variable reference

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Public listener port (default: `5553`) |
| `BASE_URL` | Yes | Public base URL, e.g. `https://relay.dicode.app` — used in relay welcome messages |
| `TLS_CERT_FILE` | No | Path to PEM TLS certificate for the public listener (skip if TLS terminated externally) |
| `TLS_KEY_FILE` | No | Path to PEM TLS private key |
| `MTLS_CERT_FILE` | No | Server cert for the mTLS control channel (falls back to `TLS_*`, then a self-signed dev cert) |
| `MTLS_KEY_FILE` | No | Private key for the mTLS control channel |
| `GITHUB_CLIENT_ID` | Per-provider | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | Per-provider | GitHub OAuth app client secret |
| `SLACK_CLIENT_ID` | Per-provider | Slack OAuth app client ID (PKCE-only, no secret) |
| `GOOGLE_CLIENT_ID` | Per-provider | Google OAuth app client ID |
| `GOOGLE_CLIENT_SECRET` | Per-provider | Google OAuth app client secret |
| `SPOTIFY_CLIENT_ID` | Per-provider | Spotify app client ID (PKCE-only) |
| `LINEAR_CLIENT_ID` | Per-provider | Linear app client ID (PKCE-only) |
| `DISCORD_CLIENT_ID` | Per-provider | Discord app client ID (PKCE-only) |
| `GITLAB_CLIENT_ID` | Per-provider | GitLab app client ID |
| `GITLAB_CLIENT_SECRET` | Per-provider | GitLab app client secret |
| `AIRTABLE_CLIENT_ID` | Per-provider | Airtable app client ID |
| `AIRTABLE_CLIENT_SECRET` | Per-provider | Airtable app client secret |
| `NOTION_CLIENT_ID` | Per-provider | Notion integration client ID |
| `NOTION_CLIENT_SECRET` | Per-provider | Notion integration client secret |
| `CONFLUENCE_CLIENT_ID` | Per-provider | Atlassian app client ID (PKCE-only) |
| `SALESFORCE_CLIENT_ID` | Per-provider | Salesforce connected app client ID (PKCE-only) |
| `STRIPE_CLIENT_ID` | Per-provider | Stripe Connect platform client ID |
| `STRIPE_CLIENT_SECRET` | Per-provider | Stripe Connect platform client secret |
| `OFFICE365_CLIENT_ID` | Per-provider | Azure AD app client ID |
| `OFFICE365_CLIENT_SECRET` | Per-provider | Azure AD app client secret |
| `AZURE_CLIENT_ID` | Per-provider | Azure AD app client ID |
| `AZURE_CLIENT_SECRET` | Per-provider | Azure AD app client secret |

See `.env.example` for registration links per provider.

---

## Relay protocol reference (v4)

All WebSocket messages are JSON text frames shaped as single-key oneof
envelopes (`{"hello": {...}}`), generated from `proto/relay.proto`.

### Handshake

The daemon dials the broker's **mTLS port** presenting a self-signed TLS
client certificate that wraps its ECDSA P-256 identity key. The broker
derives the daemon's identity from the peer certificate:
`uuid = hex(sha256(uncompressed_cert_pubkey))`. TLS 1.3 CertificateVerify
channel-binds the key — there is no application-level challenge.

```
Client → Server (immediately after the WS opens):
  { "hello": { "decrypt_pubkey": "<base64 std>" } }   // 65 bytes: 0x04 || X || Y — ECIES recipient

Server → Client (success):
  {
    "welcome": {
      "url":           "wss://relay.dicode.app/u/<uuid>/hooks/",
      "protocol":      4,
      "broker_pubkey": "<base64 SPKI DER>"   // broker's delivery-signing key; persisted by the
                                             // daemon on every connect (channel is TLS-authenticated)
    }
  }

Server → Client (failure):
  { "error": { "message": "<reason>" } }
```

WS close codes: `4400` bad hello, `4401` no client certificate presented,
`4402` client certificate key is not P-256. Both sides reject protocol < 4.

### Webhook forwarding

```
Server → Client (inbound request):
  {
    "request": {
      "id":      "<uuidv4>",
      "method":  "POST",
      "path":    "/hooks/some-task",
      "headers": { "Content-Type": { "values": ["application/json"] } },
      "body":    "<base64 encoded bytes>"
    }
  }

Client → Server (response):
  {
    "response": {
      "id":      "<same uuidv4>",
      "status":  200,
      "headers": { "Content-Type": { "values": ["application/json"] } },
      "body":    "<base64 encoded bytes>"
    }
  }
```

### OAuth token delivery

When the broker completes a code exchange, it sends a `request` message to the daemon at path `/hooks/oauth-complete`:

```json
{
  "request": {
    "id":      "<uuidv4>",
    "method":  "POST",
    "path":    "/hooks/oauth-complete",
    "headers": { "Content-Type": { "values": ["application/json"] } },
    "body":    "<base64 of OAuthTokenDeliveryPayload JSON>"
  }
}
```

Where `OAuthTokenDeliveryPayload` is:

```json
{
  "type":             "oauth_token_delivery",
  "session_id":       "<uuid>",
  "ephemeral_pubkey": "<base64, 65-byte uncompressed P-256>",
  "ciphertext":       "<base64, AES-256-GCM ciphertext + 16-byte auth tag>",
  "nonce":            "<base64, 12-byte GCM nonce>"
}
```

See [docs/providers.md](docs/providers.md) for the full ECIES decryption procedure.

---

## Security model

- **mTLS channel binding**: The daemon's identity is its TLS client certificate (a self-signed wrapper around its P-256 key). TLS 1.3 CertificateVerify covers the handshake transcript, so a signature can never be relayed to a different broker — the signature-relay/UUID-hijack class of attack against app-level challenge handshakes is structurally impossible.
- **Server authentication**: Daemons verify the broker's server certificate via normal TLS (WebPKI for the hosted relay, an explicit CA file for self-hosted brokers). The broker's delivery-signing pubkey arrives over this authenticated channel — no trust-on-first-use pinning.
- **ECDSA authentication (OAuth)**: Every broker auth request is signed by the daemon's P-256 identity key over a domain-labeled, length-prefixed preimage. The broker verifies against the public key extracted from the daemon's client certificate — no API key or shared secret required.
- **ECIES token encryption**: Tokens are encrypted with the daemon's `decrypt_pubkey` (the ECIES-only half of the split sign/decrypt identity, sent on `hello`) before entering the relay code path. The relay server never sees plaintext tokens.
- **PKCE binding**: The PKCE challenge is signed into the broker request and bound to the session. The verifier stays on the daemon and is never transmitted.
- **Single-use sessions**: Sessions are deleted immediately after the token is delivered. Replay attacks require re-running the full OAuth flow.
- **Timestamp freshness**: OAuth auth requests must be within ±30 s of server time.

See the OAuth broker design document in the dicode-core repository for the full threat model.

---

## Deployment

### Docker (recommended)

```sh
docker run -d \
  -p 5553:5553 \
  -p 5554:5554 \
  -e BASE_URL=https://relay.dicode.app \
  -e GITHUB_CLIENT_ID=xxx \
  -e GITHUB_CLIENT_SECRET=yyy \
  dicodeayo/dicode-relay
```

Also available at `ghcr.io/dicode-ayo/dicode-relay` if you prefer GitHub's registry.

### Cloudflare

Point a Cloudflare-proxied A record at your server **for the public listener
only**. Enable "WebSocket" under the Cloudflare Network settings for the
domain. Cloudflare terminates TLS; the public listener can run plain HTTP
(omit `TLS_CERT_FILE`/`TLS_KEY_FILE`).

**The mTLS port must NOT go through the Cloudflare proxy** (or any
TLS-terminating proxy): termination strips the daemon's client certificate
and every connection is rejected with close code 4401. Expose
`server.mtls.port` directly (grey-cloud DNS record) or behind an L4/TCP load
balancer with TLS passthrough.

Enable **Session Affinity** in the Cloudflare load balancer if you run multiple
instances — sessions are stored in-process.

### Self-host (nginx)

```nginx
# Public listener — TLS termination is fine here.
server {
    listen 443 ssl;
    server_name relay.dicode.app;

    location / {
        proxy_pass http://127.0.0.1:5553;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}

# mTLS control channel — TCP passthrough ONLY (stream module), never
# `listen ... ssl`: nginx must not terminate this TLS session or the
# daemon's client certificate is lost.
stream {
    server {
        listen 5554;
        proxy_pass 127.0.0.1:5554;
    }
}
```

---

## Client library

This package also publishes a TypeScript/Web-Crypto client library at
`dicode-relay/client`, used by dicode-core's built-in tasks to maintain
the WSS tunnel and run OAuth flows. The library is pure protocol + crypto —
consumers own all persistence. Example:

```ts
import { RelayClient, Identity, type StoredIdentity } from "dicode-relay/client";

// Consumer owns persistence — example using a hypothetical KV.
const stored = await myKv.get<StoredIdentity>("identity");
const identity = stored
  ? await Identity.import(stored)
  : await (async () => {
      const id = await Identity.generate();
      // StoredIdentity contains PRIVATE key material — treat it like a TLS
      // private key. Use encrypted storage (e.g. dicode.kv with the daemon's
      // secret-store backing).
      await myKv.set("identity", await id.export());
      return id;
    })();

// The client certificate wraps the identity's sign key — regenerated per
// boot, never persisted (only the public key matters to the broker).
const clientCert = await identity.mintClientCert();

const client = new RelayClient({
  serverURL: "wss://relay.example:5554/",   // the broker's mTLS port
  localPort: 8080,
  identity,
  tls: {
    certPem: clientCert.certPem,
    keyPem: clientCert.keyPem,
    // ca: selfSignedBrokerCertPem,  // only for self-hosted brokers; omit for WebPKI
  },
  onBrokerPubkey: async (b64) => {
    // Persist unconditionally — the channel is TLS-server-authenticated.
    await myKv.set("broker_pubkey", b64);
  },
  log: console,
  onStatus: (s) => console.log("status:", s),
});

await client.run();
```

The client targets Node.js 22+ and Deno (both expose `node:crypto`). It is not
browser-compatible — `node:crypto` primitives are used for HKDF, AES-GCM decrypt,
and broker signature verification. In dicode tasks, use `dicode.kv` from the
SDK to persist the `StoredIdentity` blob and the broker pubkey.

---

## Contributing

```sh
npm install
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run format:check
npm run test        # vitest
npm run test:coverage  # must pass 90% threshold
npm run build       # tsc
```

All checks must pass before opening a PR.
