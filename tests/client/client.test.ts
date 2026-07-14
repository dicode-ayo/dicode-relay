import { describe, expect, it } from "vitest";
import { createServer, type Server as HttpServer } from "node:http";
import { createServer as createNetServer, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RelayServer } from "../../src/relay/server.js";
import { Identity } from "../../src/client/identity.js";
import { RelayClient } from "../../src/client/client.js";
import { loadBrokerSigningKey } from "../../src/shared/signing.js";
import { testRelayOpts } from "../helpers.js";
import type { TofuResult } from "../../src/client/handshake.js";

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

    // 3. Build a RelayClient with an inline TOFU callback.
    const id = await Identity.generate();
    let pinnedBrokerKey: string | null = null;
    const tofuCheckAndPin = (brokerPubkeyB64: string): Promise<TofuResult> => {
      if (pinnedBrokerKey === null) {
        pinnedBrokerKey = brokerPubkeyB64;
        return Promise.resolve("new");
      }
      return Promise.resolve(pinnedBrokerKey === brokerPubkeyB64 ? "match" : "mismatch");
    };
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: `ws://127.0.0.1:${String(relayPort)}/`,
      localPort,
      identity: id,
      tofuCheckAndPin,
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

  it("dial timeout aborts cleanly and backs off — no unhandled 'error' crash", async () => {
    // A TCP server that accepts the connection but never completes the WS
    // upgrade, so the dial hangs until dialTimeoutMs fires. terminate() on a
    // still-CONNECTING socket emits 'error' on the next tick; if that isn't
    // swallowed it becomes an uncaughtException instead of a backoff.
    const conns = new Set<Socket>();
    const stuck = createNetServer((sock) => {
      // accept + hold the socket; never speak HTTP/WS
      conns.add(sock);
      sock.on("close", () => conns.delete(sock));
    });
    await new Promise<void>((r) => {
      stuck.listen(0, () => {
        r();
      });
    });
    const stuckPort = (stuck.address() as AddressInfo).port;

    const uncaught: unknown[] = [];
    const onUncaught = (e: unknown): void => {
      uncaught.push(e);
    };
    process.on("uncaughtException", onUncaught);

    const id = await Identity.generate();
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: `ws://127.0.0.1:${String(stuckPort)}/`,
      localPort: 1,
      identity: id,
      tofuCheckAndPin: () => Promise.resolve("new" as TofuResult),
      log: silentLogger(),
      dialTimeoutMs: 150,
    });
    const runPromise = client.run(ac.signal);

    // Let a couple of dial-timeout → backoff cycles elapse.
    await new Promise((r) => setTimeout(r, 600));

    ac.abort();
    // Bound the wait: abort should stop run() promptly; don't hang the test if
    // it regresses. Destroy any lingering half-open sockets so stuck.close()
    // (which waits for open connections) can resolve.
    await Promise.race([
      runPromise.catch(() => undefined),
      new Promise((r) => setTimeout(r, 3_000)),
    ]);
    process.off("uncaughtException", onUncaught);
    for (const c of conns) c.destroy();
    await new Promise<void>((r) => {
      stuck.close(() => {
        r();
      });
    });

    expect(uncaught).toEqual([]);
  }, 10_000);

  it("keeps a healthy connection past the dial timeout (timer cleared on open)", async () => {
    // Happy-path stack with a short dial timeout, then a wait longer than it
    // before forwarding: proves the dial timer is cleared on 'open' and never
    // tears an established connection down.
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

    const tmp = mkdtempSync(join(tmpdir(), "broker-key-"));
    const broker = loadBrokerSigningKey({}, tmp);
    const relay = new RelayServer(
      testRelayOpts({ baseUrl: "ws://127.0.0.1", brokerPubkey: broker.publicKeyBase64 }),
    );
    const relayPort = relay.port;

    const id = await Identity.generate();
    let pinned: string | null = null;
    const tofuCheckAndPin = (k: string): Promise<TofuResult> => {
      if (pinned === null) {
        pinned = k;
        return Promise.resolve("new");
      }
      return Promise.resolve(pinned === k ? "match" : "mismatch");
    };
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: `ws://127.0.0.1:${String(relayPort)}/`,
      localPort,
      identity: id,
      tofuCheckAndPin,
      log: silentLogger(),
      dialTimeoutMs: 150,
    });
    const runPromise = client.run(ac.signal);

    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline && !relay.hasClient(id.uuid)) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(relay.hasClient(id.uuid)).toBe(true);

    // Wait well past the 150ms dial timeout — a stale timer would kill it here.
    await new Promise((r) => setTimeout(r, 500));
    expect(relay.hasClient(id.uuid)).toBe(true);

    const resp = await relay.forward(
      id.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("hello"),
    );
    expect(resp.status).toBe(200);
    expect(receivedBody).toBe("hello");

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
