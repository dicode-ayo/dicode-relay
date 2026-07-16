// Spike A server: mTLS-style https server (requestCert, no CA verification)
// with a WSS endpoint that echoes the peer certificate's subject CN, or "NONE".
//
// Usage: node spikes/spike-a-server.mjs <certDir> [port]
import { createServer } from "node:https";
import { readFileSync } from "node:fs";
import { WebSocketServer } from "ws";

const certDir = process.argv[2];
const port = Number(process.argv[3] ?? 15554);

const server = createServer({
  cert: readFileSync(`${certDir}/server-cert.pem`),
  key: readFileSync(`${certDir}/server-key.pem`),
  requestCert: true,
  rejectUnauthorized: false,
});

const wss = new WebSocketServer({ server });
wss.on("connection", (ws, req) => {
  const cert = req.socket.getPeerX509Certificate?.() ?? null;
  const subject = cert?.subject ?? null;
  // Also report the raw pubkey so Spike B can assert SPKI equality end-to-end.
  const spkiB64 = cert ? cert.publicKey.export({ type: "spki", format: "der" }).toString("base64") : null;
  ws.send(JSON.stringify({ subject: subject ?? "NONE", spkiB64 }));
  ws.close();
});

server.listen(port, "127.0.0.1", () => {
  console.log(`spike-a server listening on ${port}`);
});
