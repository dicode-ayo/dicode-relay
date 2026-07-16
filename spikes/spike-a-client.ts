// Spike A client: connect to the spike server over wss presenting a TLS client
// certificate through npm:ws under Deno.
//
// TLS options MUST ride on an https.Agent — Deno's node:https drops
// per-request TLS options ({cert,key,ca} directly in the ws options object)
// and ignores createConnection; agent-carried options work on both Deno and
// Node.
//
// Usage: deno run --allow-net --allow-read --allow-env spikes/spike-a-client.ts <certDir> [port]
import WebSocket from "npm:ws@8";
import https from "node:https";

const certDir = Deno.args[0];
const port = Number(Deno.args[1] ?? 15554);

const cert = Deno.readTextFileSync(`${certDir}/client-cert.pem`);
const key = Deno.readTextFileSync(`${certDir}/client-key.pem`);
const ca = Deno.readTextFileSync(`${certDir}/server-cert.pem`);

const ws = new WebSocket(`wss://127.0.0.1:${port}/`, {
  agent: new https.Agent({ cert, key, ca }),
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
console.log("server saw peer cert subject:", JSON.stringify(parsed.subject));
if (parsed.subject === "NONE" || !parsed.subject.includes("spike-client")) {
  console.error("SPIKE A: FAIL — client certificate did not reach the server");
  Deno.exit(1);
}
console.log("SPIKE A: PASS");
Deno.exit(0);
