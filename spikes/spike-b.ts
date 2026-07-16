// Spike B: mint a self-signed X.509 client cert from a WebCrypto P-256 ECDSA
// keypair via @peculiar/x509 (under Deno), then present it over mTLS through
// npm:ws + https.Agent and assert the server-observed SPKI matches the key.
//
// Usage: deno run --allow-net --allow-read --allow-env spikes/spike-b.ts <certDir> [port]
import * as x509 from "npm:@peculiar/x509@1";
import WebSocket from "npm:ws@8";
import https from "node:https";

const certDir = Deno.args[0];
const port = Number(Deno.args[1] ?? 15554);
const ca = Deno.readTextFileSync(`${certDir}/server-cert.pem`);

// 1. WebCrypto P-256 ECDSA keypair — same shape as the relay Identity sign key.
const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

// 2. Self-signed cert. CA:FALSE basicConstraints is required — rustls (Deno's
//    TLS stack) rejects CA-flagged certs used as end-entity (CaUsedAsEndEntity).
x509.cryptoProvider.set(crypto);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=spike-b-client",
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2036-01-01T00:00:00Z"),
  signingAlgorithm: alg,
  keys,
  extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
});
const certPem = cert.toString("pem");

// 3. Key as PKCS8 PEM.
const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
const keyPem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;

// 4. Expected SPKI (what the server should observe on the peer cert).
const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
const expectedSpkiB64 = btoa(String.fromCharCode(...new Uint8Array(spki)));

console.log("minted cert:\n" + certPem.slice(0, 120) + "...");

// 5. Present it over mTLS.
const ws = new WebSocket(`wss://127.0.0.1:${port}/`, {
  agent: new https.Agent({ cert: certPem, key: keyPem, ca }),
});

const result = await new Promise<string>((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("timeout")), 10_000);
  ws.on("message", (data: unknown) => {
    clearTimeout(timer);
    resolve(String(data));
  });
  ws.on("error", (err: Error) => {
    clearTimeout(timer);
    reject(err);
  });
});

const parsed = JSON.parse(result) as { subject: string; spkiB64: string | null };
console.log("server saw subject:", parsed.subject);
console.log("SPKI match:", parsed.spkiB64 === expectedSpkiB64);
if (!parsed.subject.includes("spike-b-client") || parsed.spkiB64 !== expectedSpkiB64) {
  console.error("SPIKE B: FAIL");
  Deno.exit(1);
}
console.log("SPIKE B: PASS");
Deno.exit(0);
