/**
 * Multi-URL fan-out: one RelayClient holding an independent mTLS control
 * connection per broker instance, all sharing one identity/uuid so every
 * instance can forward locally (issue #109).
 */

import { describe, expect, it } from "vitest";
import { createServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";

import { Identity } from "../../src/client/identity.js";
import { RelayClient, type RelayStatus } from "../../src/client/client.js";
import { RelayServer } from "../../src/relay/server.js";
import {
  startMtlsRelay,
  testServerCert,
  testRelayOpts,
  testDaemon,
  testBrokerKey,
  type MtlsRelayFixture,
  type TestDaemon,
} from "../helpers.js";

function silentLogger() {
  const noop = (_msg: string, _meta?: Record<string, unknown>): void => {
    /* intentionally silent */
  };
  return { info: noop, warn: noop, error: noop };
}

function clientTls(
  daemon: TestDaemon,
  ca: string,
): { certPem: string; keyPem: string; ca: string } {
  return { certPem: daemon.cert.certPem, keyPem: daemon.cert.keyPem, ca };
}

/** Local HTTP app the client forwards webhooks to; echoes the body back. */
async function startLocalEcho(): Promise<{ port: number; close: () => Promise<void> }> {
  const server: HttpServer = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(`echo:${Buffer.concat(chunks).toString("utf8")}`);
    });
  });
  await new Promise<void>((r) => {
    server.listen(0, r);
  });
  return {
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise<void>((r) => {
        server.close(() => {
          r();
        });
      }),
  };
}

/**
 * Start an mTLS relay bound to a *specific* port (0 for ephemeral). Mirrors
 * helpers.startMtlsRelay but lets a test restart an instance on the same port
 * to prove reconnect.
 */
async function startRelayOnPort(
  port: number,
  overrides: { baseUrl: string; brokerPubkey?: string },
): Promise<MtlsRelayFixture> {
  const serverCert = await testServerCert();
  const httpsServer = createHttpsServer({
    cert: serverCert.certPem,
    key: serverCert.keyPem,
    requestCert: true,
    rejectUnauthorized: false,
  });
  const relay = new RelayServer(testRelayOpts(httpsServer, overrides));
  await new Promise<void>((resolve, reject) => {
    httpsServer.once("error", reject);
    httpsServer.listen(port, "127.0.0.1", () => {
      httpsServer.removeListener("error", reject);
      resolve();
    });
  });
  const boundPort = (httpsServer.address() as AddressInfo).port;
  return {
    relay,
    httpsServer,
    port: boundPort,
    url: `wss://127.0.0.1:${String(boundPort)}`,
    ca: serverCert.certPem,
    close: async () => {
      await relay.close();
      await new Promise<void>((resolve) => {
        if (!httpsServer.listening) {
          resolve();
          return;
        }
        httpsServer.close(() => {
          resolve();
        });
      });
    },
  };
}

/** Poll until `fn()` is truthy or the deadline elapses. */
async function waitUntil(fn: () => boolean, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("waitUntil timed out");
}

describe("RelayClient config validation", () => {
  const base = {
    localPort: 1,
    tls: { certPem: "x", keyPem: "y" },
    log: silentLogger(),
  };

  it("rejects setting both serverURL and serverURLs", async () => {
    const id = await Identity.generate();
    expect(
      () =>
        new RelayClient({
          ...base,
          identity: id,
          serverURL: "wss://a",
          serverURLs: ["wss://b"],
        }),
    ).toThrow(/either serverURL or serverURLs/);
  });

  it("rejects setting neither", async () => {
    const id = await Identity.generate();
    expect(() => new RelayClient({ ...base, identity: id })).toThrow(
      /one of serverURL or serverURLs/,
    );
  });

  it("rejects an empty serverURLs list", async () => {
    const id = await Identity.generate();
    expect(() => new RelayClient({ ...base, identity: id, serverURLs: [] })).toThrow(
      /must not be empty/,
    );
  });

  it("rejects duplicate URLs in serverURLs", async () => {
    const id = await Identity.generate();
    expect(
      () => new RelayClient({ ...base, identity: id, serverURLs: ["wss://a", "wss://a"] }),
    ).toThrow(/duplicate server URL/);
  });
});

describe("RelayClient single-URL back-compat", () => {
  it("serverURL and a one-element serverURLs behave identically (flat status, no endpoints)", async () => {
    const echo = await startLocalEcho();
    const broker = testBrokerKey();
    const fixture = await startMtlsRelay({
      baseUrl: "ws://127.0.0.1",
      brokerPubkey: broker.publicKeyBase64,
    });
    const daemon = await testDaemon(fixture);

    for (const opt of [{ serverURL: fixture.url }, { serverURLs: [fixture.url] }]) {
      const statuses: RelayStatus[] = [];
      const ac = new AbortController();
      const client = new RelayClient({
        ...opt,
        localPort: echo.port,
        identity: daemon.identity,
        tls: clientTls(daemon, fixture.ca),
        log: silentLogger(),
        onStatus: (s) => statuses.push(s),
      });
      const run = client.run(ac.signal);
      await waitUntil(() => statuses.some((s) => s.connected));

      const connected = statuses.find((s) => s.connected);
      expect(connected?.hook_base_url).toBe(`ws://127.0.0.1/u/${daemon.identity.uuid}/hooks/`);
      expect(connected?.broker_pubkey).toBe(broker.publicKeyBase64);
      // Single-URL keeps the flat shape — no per-endpoint breakdown.
      expect(connected?.endpoints).toBeUndefined();

      ac.abort();
      await run.catch(() => undefined);
    }
    await fixture.close();
    await echo.close();
  }, 15_000);
});

describe("RelayClient multi-URL fan-out", () => {
  it("connects to every instance with the same uuid and per-connection broker keys", async () => {
    const echo = await startLocalEcho();
    const brokerA = testBrokerKey();
    const brokerB = testBrokerKey();
    const a = await startMtlsRelay({
      baseUrl: "ws://broker-a",
      brokerPubkey: brokerA.publicKeyBase64,
    });
    const b = await startMtlsRelay({
      baseUrl: "ws://broker-b",
      brokerPubkey: brokerB.publicKeyBase64,
    });
    const daemon = await testDaemon(a);

    const announcedKeys: string[] = [];
    const statuses: RelayStatus[] = [];
    const ac = new AbortController();
    const client = new RelayClient({
      serverURLs: [a.url, b.url],
      localPort: echo.port,
      identity: daemon.identity,
      tls: clientTls(daemon, a.ca),
      onBrokerPubkey: (k) => {
        announcedKeys.push(k);
        return Promise.resolve();
      },
      log: silentLogger(),
      onStatus: (s) => statuses.push(s),
    });
    const run = client.run(ac.signal);

    // The same daemon uuid registers on BOTH instances.
    await waitUntil(() => a.relay.hasClient(daemon.identity.uuid));
    await waitUntil(() => b.relay.hasClient(daemon.identity.uuid));

    // Each connection's welcome is passed through independently.
    await waitUntil(() => announcedKeys.length === 2);
    expect(new Set(announcedKeys)).toEqual(
      new Set([brokerA.publicKeyBase64, brokerB.publicKeyBase64]),
    );

    // Either instance forwards to the one local daemon.
    for (const inst of [a, b]) {
      const resp = await inst.relay.forward(
        daemon.identity.uuid,
        "POST",
        "/hooks/test",
        { "Content-Type": ["text/plain"] },
        Buffer.from("hi"),
      );
      expect(resp.status).toBe(200);
      expect(Buffer.from(resp.body, "base64").toString("utf8")).toBe("echo:hi");
    }

    // Aggregate reports connected with a two-endpoint breakdown.
    await waitUntil(() => {
      const s = statuses.at(-1);
      return s?.connected === true && (s.endpoints?.filter((e) => e.connected).length ?? 0) === 2;
    });
    const latest = statuses.at(-1);
    expect(latest?.endpoints?.map((e) => e.server_url).sort()).toEqual([a.url, b.url].sort());

    ac.abort();
    await run.catch(() => undefined);
    await a.close();
    await b.close();
    await echo.close();
  }, 20_000);

  it("one instance dropping reconnects only that connection; the other keeps forwarding", async () => {
    const echo = await startLocalEcho();
    const brokerA = testBrokerKey();
    const brokerB = testBrokerKey();
    let a = await startRelayOnPort(0, {
      baseUrl: "ws://broker-a",
      brokerPubkey: brokerA.publicKeyBase64,
    });
    const b = await startMtlsRelay({
      baseUrl: "ws://broker-b",
      brokerPubkey: brokerB.publicKeyBase64,
    });
    const portA = a.port;
    const daemon = await testDaemon(a);

    const ac = new AbortController();
    const client = new RelayClient({
      serverURLs: [a.url, b.url],
      localPort: echo.port,
      identity: daemon.identity,
      tls: clientTls(daemon, a.ca),
      log: silentLogger(),
      dialTimeoutMs: 500,
    });
    const run = client.run(ac.signal);

    await waitUntil(() => a.relay.hasClient(daemon.identity.uuid));
    await waitUntil(() => b.relay.hasClient(daemon.identity.uuid));

    // Kill instance A only.
    await a.close();

    // B stays connected the whole time and keeps forwarding.
    expect(b.relay.hasClient(daemon.identity.uuid)).toBe(true);
    const viaB = await b.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("still-up"),
    );
    expect(viaB.status).toBe(200);
    expect(Buffer.from(viaB.body, "base64").toString("utf8")).toBe("echo:still-up");

    // Bring A back on the same port — the A connection reconnects on its own.
    a = await startRelayOnPort(portA, {
      baseUrl: "ws://broker-a",
      brokerPubkey: brokerA.publicKeyBase64,
    });
    await waitUntil(() => a.relay.hasClient(daemon.identity.uuid), 12_000);

    const viaA = await a.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("back"),
    );
    expect(viaA.status).toBe(200);
    expect(Buffer.from(viaA.body, "base64").toString("utf8")).toBe("echo:back");

    ac.abort();
    await run.catch(() => undefined);
    await a.close();
    await b.close();
    await echo.close();
  }, 25_000);

  it("keeps retrying while all instances are down, then recovers", async () => {
    const echo = await startLocalEcho();
    const brokerA = testBrokerKey();
    const brokerB = testBrokerKey();
    let a = await startRelayOnPort(0, {
      baseUrl: "ws://broker-a",
      brokerPubkey: brokerA.publicKeyBase64,
    });
    let b = await startRelayOnPort(0, {
      baseUrl: "ws://broker-b",
      brokerPubkey: brokerB.publicKeyBase64,
    });
    const portA = a.port;
    const portB = b.port;
    const daemon = await testDaemon(a);

    const statuses: RelayStatus[] = [];
    const ac = new AbortController();
    const client = new RelayClient({
      serverURLs: [a.url, b.url],
      localPort: echo.port,
      identity: daemon.identity,
      tls: clientTls(daemon, a.ca),
      log: silentLogger(),
      dialTimeoutMs: 500,
      onStatus: (s) => statuses.push(s),
    });
    const run = client.run(ac.signal);

    await waitUntil(() => a.relay.hasClient(daemon.identity.uuid));
    await waitUntil(() => b.relay.hasClient(daemon.identity.uuid));

    // Take both down.
    await a.close();
    await b.close();
    await waitUntil(() => statuses.at(-1)?.connected === false);

    // run() must NOT have resolved — it keeps retrying until abort.
    const settled = await Promise.race([
      run.then(() => "resolved" as const),
      new Promise<"pending">((r) => {
        setTimeout(() => {
          r("pending");
        }, 300);
      }),
    ]);
    expect(settled).toBe("pending");

    // Bring both back on their original ports; the client reconnects.
    a = await startRelayOnPort(portA, {
      baseUrl: "ws://broker-a",
      brokerPubkey: brokerA.publicKeyBase64,
    });
    b = await startRelayOnPort(portB, {
      baseUrl: "ws://broker-b",
      brokerPubkey: brokerB.publicKeyBase64,
    });
    await waitUntil(() => a.relay.hasClient(daemon.identity.uuid), 15_000);
    await waitUntil(() => b.relay.hasClient(daemon.identity.uuid), 15_000);
    await waitUntil(() => statuses.at(-1)?.connected === true);

    ac.abort();
    await run.catch(() => undefined);
    await a.close();
    await b.close();
    await echo.close();
  }, 30_000);
});
