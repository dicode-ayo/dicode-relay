# dicode-relay

A production-ready TypeScript/Node.js service that combines an OAuth broker and a WebSocket relay tunnel in a single process. It lets local dicode daemons (running behind NAT on developer laptops) receive OAuth callbacks and inbound webhooks without a public port, ngrok, or per-user OAuth app registration — the broker holds dicode's shared `client_id`/`client_secret` for each provider, executes the full authorization-code flow, and delivers the encrypted access token directly to the daemon over the relay tunnel.

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│  User's machine                                              │
│                                                              │
│  ┌──────────────────┐   WSS (persistent)                    │
│  │  dicode daemon   │◄──────────────────────────────────┐   │
│  │                  │                                   │   │
│  │  relay.Client    │   /hooks/oauth-complete delivery  │   │
│  │  (Go, PR #79)    │◄── forwarded over WS ─────────────┤   │
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
   │    ?session=...                  │   │  │  - challenge/response  │  │
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
               │  (provider OAuth)    │  │  PORT 443 (WSS + HTTPS)      │
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
docker pull ghcr.io/dicode-ayo/dicode-relay:latest
docker run -p 5553:5553 --env-file .env ghcr.io/dicode-ayo/dicode-relay:latest
```

---

## Environment variable reference

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Port to listen on (default: `5553`) |
| `BASE_URL` | Yes | Public base URL, e.g. `https://relay.dicode.app` — used in relay welcome messages |
| `TLS_CERT_FILE` | No | Path to PEM TLS certificate (skip if TLS terminated externally) |
| `TLS_KEY_FILE` | No | Path to PEM TLS private key |
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

## Relay protocol reference

All WebSocket messages are JSON text frames.

### Handshake

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

### OAuth token delivery

When the broker completes a code exchange, it sends a `request` message to the daemon at path `/hooks/oauth-complete`:

```json
{
  "type":    "request",
  "id":      "<uuidv4>",
  "method":  "POST",
  "path":    "/hooks/oauth-complete",
  "headers": { "Content-Type": ["application/json"] },
  "body":    "<base64 of OAuthTokenDeliveryPayload JSON>"
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

- **ECDSA authentication**: Every broker auth request is signed by the daemon's P-256 identity key. The broker verifies the signature against the public key registered in the relay client registry — no API key or shared secret required.
- **ECIES token encryption**: Tokens are encrypted with the daemon's public key before entering the relay code path. The relay server never sees plaintext tokens.
- **PKCE binding**: The PKCE challenge is signed into the broker request and bound to the session. The verifier stays on the daemon and is never transmitted.
- **Single-use sessions**: Sessions are deleted immediately after the token is delivered. Replay attacks require re-running the full OAuth flow.
- **Timestamp + nonce replay prevention**: Auth requests must be within ±30 s of server time. Relay handshake nonces are tracked for 60 s.

See [docs/design/oauth-broker.md](../dicode/docs/design/oauth-broker.md) for the full threat model.

---

## Deployment

### Docker (recommended)

```sh
docker build -t dicode-relay .
docker run -d \
  -p 5553:5553 \
  -e BASE_URL=https://relay.dicode.app \
  -e GITHUB_CLIENT_ID=xxx \
  -e GITHUB_CLIENT_SECRET=yyy \
  dicode-relay
```

### Cloudflare

Point a Cloudflare-proxied A record at your server. Enable "WebSocket" under
the Cloudflare Network settings for the domain. Cloudflare terminates TLS;
the service listens on plain HTTP (omit `TLS_CERT_FILE`/`TLS_KEY_FILE`).

Enable **Session Affinity** in the Cloudflare load balancer if you run multiple
instances — sessions are stored in-process.

### Self-host (nginx)

```nginx
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
```

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
