# Supported OAuth Providers

This document describes every OAuth provider supported by dicode-relay, the required
environment variables, and any provider-specific quirks.

---

## Provider table

| Provider | Grant key | PKCE | Secret required | Default scopes | Register |
|---|---|---|---|---|---|
| GitHub | `github` | Yes | Yes | `user repo` | [GitHub OAuth Apps](https://github.com/settings/applications/new) |
| Slack | `slack` | Yes | No | `channels:read` | [Slack API](https://api.slack.com/apps) |
| Google | `google` | Yes | Yes | `https://www.googleapis.com/auth/userinfo.email` | [Google Cloud Console](https://console.cloud.google.com/apis/credentials) |
| Spotify | `spotify` | Yes | No | `user-read-private user-read-email` | [Spotify Developer Dashboard](https://developer.spotify.com/dashboard) |
| Linear | `linear` | Yes | No | `read` | [Linear API Settings](https://linear.app/settings/api) |
| Discord | `discord` | Yes | No | `identify email` | [Discord Developer Portal](https://discord.com/developers/applications) |
| GitLab | `gitlab` | Yes | Yes | `read_user read_api` | [GitLab Applications](https://gitlab.com/-/user_settings/applications) |
| Airtable | `airtable` | Yes | Yes | `data.records:read` | [Airtable OAuth](https://airtable.com/create/oauth) |
| Notion | `notion` | No | Yes | *(empty)* | [Notion Integrations](https://www.notion.so/my-integrations) |
| Confluence | `confluence` | Yes | No | `read:me read:confluence-content.all offline_access` | [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/) |
| Salesforce | `salesforce` | Yes | No | `api refresh_token` | [Salesforce Connected Apps](https://login.salesforce.com/setup/secur/RemoteAccessAuthorizationPage.apexp) |
| Stripe | `stripe` | No | Yes | `read_write` | [Stripe Connect](https://dashboard.stripe.com/settings/connect) |
| Office 365 | `office365` | Yes | Yes | `offline_access User.Read Mail.Read` | [Azure App Registration](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) |
| Azure AD | `azure` | Yes | Yes | `openid profile email offline_access` | [Azure App Registration](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) |

---

## Provider quirks

### Notion
Notion does not support PKCE. The broker uses HTTP Basic authentication
(`client_id:client_secret`) for the token exchange. The `scope` parameter is
ignored by Notion — the integration's permissions are configured in the Notion
UI at integration setup time.

### Stripe
Stripe Connect uses `client_secret` for the token exchange (not PKCE). The
token response includes `stripe_user_id` in addition to `access_token` — the
daemon receives all fields from Grant in the encrypted payload.

### Slack
Slack supports PKCE for its OAuth 2.0 flow. No `client_secret` is required
when PKCE is used. Slack ignores dynamically overridden scopes in some flows;
test carefully if requesting non-default scopes.

### Google
Requires `https://` scopes. The default scope is `userinfo.email`. For
Drive/Calendar/etc., override via `?scope=` in the broker auth URL.

### Office 365 / Azure AD
Both use Microsoft's identity platform. `office365` targets the multi-tenant
`/common` endpoint; `azure` can be used for single-tenant apps. Both require
`offline_access` for refresh tokens.

### Confluence (Atlassian)
Uses Atlassian's new OAuth 2.0 (3LO) with PKCE. Register at
developer.atlassian.com. The `offline_access` scope is required for refresh
tokens.

---

## ECIES token delivery format

When the broker completes a code exchange, it encrypts the token payload and
delivers it to the daemon over the relay WebSocket as a `request` message at
path `/hooks/oauth-complete`.

### OAuthTokenDeliveryPayload

```json
{
  "type":             "oauth_token_delivery",
  "session_id":       "550e8400-e29b-41d4-a716-446655440000",
  "ephemeral_pubkey": "<base64, 65-byte uncompressed P-256 point>",
  "ciphertext":       "<base64, see below>",
  "nonce":            "<base64, 12-byte AES-GCM nonce>"
}
```

### Encryption algorithm

```
ephemeral_key   = generate P-256 keypair
shared_secret   = ECDH(ephemeral_private, daemon_pubkey)
enc_key         = HKDF-SHA256(
                    ikm   = shared_secret,
                    salt  = session_id (UTF-8 bytes),
                    info  = "dicode-oauth-token",
                    len   = 32
                  )
ciphertext      = AES-256-GCM(enc_key, nonce=random_12_bytes, plaintext=JSON.stringify(tokens))
```

### AES-GCM authentication tag convention

**The last 16 bytes of `ciphertext` (after base64 decoding) are the AES-GCM
authentication tag.** The Go daemon must split them off before calling
`aesGCM.Open`:

```go
ctWithTag := base64Decode(payload.Ciphertext)
ct  := ctWithTag[:len(ctWithTag)-16]
tag := ctWithTag[len(ctWithTag)-16:]

block, _ := aes.NewCipher(encKey)
gcm, _   := cipher.NewGCM(block)
gcm.SetTag(tag)  // or use Open with explicit tag handling
plaintext, err := gcm.Open(nil, nonce, ct, nil)
```

This convention matches Node.js's `crypto.createCipheriv("aes-256-gcm")` which
appends the tag via `cipher.getAuthTag()`.

### Go decryption pseudocode

```go
func decryptOAuthToken(daemonPriv *ecdh.PrivateKey, sessionID string, payload OAuthTokenDeliveryPayload) ([]byte, error) {
    ephPub, _ := ecdh.P256().NewPublicKey(base64Decode(payload.EphemeralPubkey))
    sharedSecret, _ := daemonPriv.ECDH(ephPub)

    encKey := hkdf.New(sha256.New, sharedSecret, []byte(sessionID), []byte("dicode-oauth-token"))
    key := make([]byte, 32)
    io.ReadFull(encKey, key)

    nonce := base64Decode(payload.Nonce)  // 12 bytes
    ctWithTag := base64Decode(payload.Ciphertext)
    ct  := ctWithTag[:len(ctWithTag)-16]
    tag := ctWithTag[len(ctWithTag)-16:]

    block, _ := aes.NewCipher(key)
    gcm, _   := cipher.NewGCM(block)

    // Reconstruct ciphertext+tag in the format gcm.Open expects
    ciphertextForOpen := append(ct, tag...)
    plaintext, err := gcm.Open(nil, nonce, ciphertextForOpen, nil)
    return plaintext, err
}
```

---

## Adding a new provider

1. Add a `ProviderConfig` entry to `src/broker/providers.ts`.
2. Add the `CLIENT_ID` (and optionally `CLIENT_SECRET`) env vars to `.env.example`.
3. Add a row to the table above.
4. Verify Grant supports the provider: `https://github.com/simov/grant#supported-providers`.
5. Run `npm run test:coverage` to ensure nothing regressed.
