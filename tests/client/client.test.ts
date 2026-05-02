import { describe, expect, it } from "vitest";
import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RelayServer } from "../../src/relay/server.js";
import { Identity } from "../../src/client/identity.js";
import { MemoryKv } from "../../src/client/kv-adapter.js";
import { TofuStore } from "../../src/client/tofu.js";
import { RelayClient } from "../../src/client/client.js";
import { loadBrokerSigningKey } from "../../src/shared/signing.js";
import { testRelayOpts } from "../helpers.js";

function silentLogger() {
  const noop = (_msg: string, _meta?: Record<string, unknown>): void => {
    /* intentionally silent */
  };
  return { info: noop, warn: noop, error: noop };
}

describe("RelayClient end-to-end", () => {
  it("connects to RelayServer, completes handshake, forwards request and response", async () => {
    // 1. Start a local HTTP server that the client will forward webhooks to.
    let receivedBody = "";
    const localApp: HttpServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => {
        chunks.push(c);
      });
      req.on("end", () => {
        receivedBody = Buffer.concat(chunks).toString("utf8");
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(`echo:${receivedBody}`);
      });
    });
    await new Promise<void>((r) => {
      localApp.listen(0, () => {
        r();
      });
    });
    const localPort = (localApp.address() as AddressInfo).port;

    // 2. Start RelayServer on a random port (port: 0 → OS assigns a free port).
    const tmp = mkdtempSync(join(tmpdir(), "broker-key-"));
    const broker = loadBrokerSigningKey({}, tmp);
    const relay = new RelayServer(
      testRelayOpts({
        baseUrl: "ws://127.0.0.1",
        brokerPubkey: broker.publicKeyBase64,
      }),
    );
    const relayPort = relay.port;

    // 3. Build a RelayClient.
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const tofu = new TofuStore(new MemoryKv());
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: `ws://127.0.0.1:${String(relayPort)}/`,
      localPort,
      identity: id,
      tofu,
      log: silentLogger(),
    });
    const runPromise = client.run(ac.signal);

    // 4. Wait for the client to register on the relay (poll for ~2s).
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline && !relay.hasClient(id.uuid)) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(relay.hasClient(id.uuid)).toBe(true);

    // 5. Forward a request through the relay → client → local app.
    const resp = await relay.forward(
      id.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("hello"),
    );
    expect(resp.status).toBe(200);
    expect(Buffer.from(resp.body, "base64").toString("utf8")).toBe("echo:hello");
    expect(receivedBody).toBe("hello");

    // 6. Tear down.
    ac.abort();
    await runPromise.catch(() => undefined);
    await relay.close();
    await new Promise<void>((r) => {
      localApp.close(() => {
        r();
      });
    });
  }, 10_000);
});
