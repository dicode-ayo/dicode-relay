# mTLS feasibility spikes (protocol v4)

Go/no-go gate for replacing the TOFU handshake with mTLS: can a Deno-hosted
client (the dicode `relay-client` buildin task, Deno 2.3.3) present a TLS
client certificate through `npm:ws`, and can it mint that certificate from its
existing WebCrypto P-256 identity key?

**Verdict: GO.** Both spikes pass under Deno 2.3.3 and Node 22.

## Running

```bash
# certs: P-256 server + client certs, basicConstraints CA:FALSE (see below)
CERTS=/tmp/spike-certs && mkdir -p $CERTS && cd $CERTS
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem
openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE"
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -x509 -key client-key.pem -out client-cert.pem -days 30 \
  -subj "/CN=spike-client" -addext "basicConstraints=critical,CA:FALSE"

node spikes/spike-a-server.mjs $CERTS 15554 &
deno run --allow-net --allow-read --allow-env spikes/spike-a-client.ts $CERTS 15554
deno run --allow-net --allow-read --allow-env spikes/spike-b.ts $CERTS 15554
```

## Findings

1. **TLS options must ride on an `https.Agent`.** Under Deno's node-compat,
   `new WebSocket(url, {cert, key, ca})` fails (`node:https` drops per-request
   TLS options) and `createConnection` is invoked but its socket unused. What
   works — on both Deno and Node — is
   `new WebSocket(url, { agent: new https.Agent({ cert, key, ca }) })`.
2. **Self-signed server certs need `basicConstraints: CA:FALSE`.** Deno's TLS
   stack is rustls, which rejects CA-flagged certificates presented as
   end-entity (`CaUsedAsEndEntity`). openssl's `req -x509` default of `CA:TRUE`
   is therefore unusable; cert generation must set CA:FALSE explicitly.
3. **`@peculiar/x509` mints usable certs from WebCrypto keys** (pure JS on
   WebCrypto, no cert-creation API exists in node:crypto). Node's TLS layer
   parses the minted cert and `getPeerX509Certificate()` reports an SPKI
   byte-identical to the WebCrypto key's — so the broker can derive
   `uuid = sha256(pubkey)` from the peer cert.
