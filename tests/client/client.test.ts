import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server as HttpServer } from "node:http";
import { createServer as createNetServer, type Socket } from "node:net";
import type { AddressInfo } from "node:net";

import { Identity } from "../../src/client/identity.js";
import { RelayClient, type RelayStatus } from "../../src/client/client.js";
import { loadBrokerSigningKey, type BrokerSigningKey } from "../../src/shared/signing.js";
import { startMtlsRelay, testDaemon, type MtlsRelayFixture, type TestDaemon } from "../helpers.js";

function silentLogger() {
  const noop = (_msg: string, _meta?: Record<string, unknown>): void => {
    /* intentionally silent */
  };
  return { info: noop, warn: noop, error: noop };
}

/** In-memory broker signing key — no disk writes. */
function ephemeralBrokerKey(): BrokerSigningKey {
  const pair = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return loadBrokerSigningKey({ BROKER_SIGNING_KEY: pair.privateKey }, "/tmp");
}

/** Local HTTP app the client forwards webhooks to; echoes the body back. */
async function startLocalEcho(): Promise<{
  server: HttpServer;
  port: number;
  received: () => string;
  close: () => Promise<void>;
}> {
  let receivedBody = "";
  const server = createServer((req, res) => {
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
    server.listen(0, () => {
      r();
    });
  });
  return {
    server,
    port: (server.address() as AddressInfo).port,
    received: () => receivedBody,
    close: () =>
      new Promise<void>((r) => {
        server.close(() => {
          r();
        });
      }),
  };
}

function clientTls(
  daemon: TestDaemon,
  fixture: MtlsRelayFixture,
): { certPem: string; keyPem: string; ca: string } {
  return { certPem: daemon.cert.certPem, keyPem: daemon.cert.keyPem, ca: fixture.ca };
}

/** Resolves when the relay registers the given uuid. */
function waitForRegistration(fixture: MtlsRelayFixture, uuid: string): Promise<void> {
  return new Promise<void>((resolve) => {
    if (fixture.relay.hasClient(uuid)) {
      resolve();
      return;
    }
    const onConnected = (u: string): void => {
      if (u === uuid) {
        fixture.relay.removeListener("client:connected", onConnected);
        resolve();
      }
    };
    fixture.relay.on("client:connected", onConnected);
  });
}

describe("RelayClient end-to-end", () => {
  it("connects over mTLS, completes handshake, forwards request and response", async () => {
    const localApp = await startLocalEcho();
    const broker = ephemeralBrokerKey();
    const fixture = await startMtlsRelay({
      baseUrl: "ws://127.0.0.1",
      brokerPubkey: broker.publicKeyBase64,
    });
    const daemon = await testDaemon(fixture);

    // onBrokerPubkey must be awaited BEFORE the status flips to connected.
    const announcedKeys: string[] = [];
    let brokerKeyPersisted = false;
    const onBrokerPubkey = (k: string): Promise<void> => {
      announcedKeys.push(k);
      return new Promise((r) => {
        setImmediate(() => {
          brokerKeyPersisted = true;
          r();
        });
      });
    };

    const statuses: RelayStatus[] = [];
    let persistedWhenConnected: boolean | undefined;
    let signalConnected: (() => void) | undefined;
    const clientConnected = new Promise<void>((resolve) => {
      signalConnected = resolve;
    });
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: fixture.url,
      localPort: localApp.port,
      identity: daemon.identity,
      tls: clientTls(daemon, fixture),
      onBrokerPubkey,
      onStatus: (s) => {
        statuses.push({ ...s });
        if (s.connected && persistedWhenConnected === undefined) {
          persistedWhenConnected = brokerKeyPersisted;
          signalConnected?.();
        }
      },
      log: silentLogger(),
    });
    const runPromise = client.run(ac.signal);

    // Wait for the client to report connected (not merely for the relay-side
    // registration): the client only starts serving request frames after it
    // has awaited onBrokerPubkey, and a forward sent before that would race
    // the serve() listener attachment.
    await clientConnected;
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    const resp = await fixture.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("hello"),
    );
    expect(resp.status).toBe(200);
    expect(Buffer.from(resp.body, "base64").toString("utf8")).toBe("echo:hello");
    expect(localApp.received()).toBe("hello");

    // Broker pubkey announced in welcome → surfaced through the callback,
    // and awaited before the connected status was reported.
    expect(announcedKeys).toEqual([broker.publicKeyBase64]);
    expect(persistedWhenConnected).toBe(true);

    const connectedStatus = statuses.find((s) => s.connected);
    expect(connectedStatus).toBeDefined();
    expect(connectedStatus?.hook_base_url).toBe(`ws://127.0.0.1/u/${daemon.identity.uuid}/hooks/`);
    expect(connectedStatus?.broker_pubkey).toBe(broker.publicKeyBase64);

    ac.abort();
    await runPromise.catch(() => undefined);
    await fixture.close();
    await localApp.close();
  }, 10_000);

  it("does not lose a request forwarded while onBrokerPubkey is still awaiting", async () => {
    // The broker registers the daemon (and can start forwarding) as soon as
    // it sends welcome — potentially before the client finishes awaiting the
    // consumer's onBrokerPubkey persistence. A frame arriving in that window
    // must be buffered by the handshake adapter and replayed into serve(),
    // not dropped into a listener-less gap.
    const localApp = await startLocalEcho();
    const broker = ephemeralBrokerKey();
    const fixture = await startMtlsRelay({
      baseUrl: "ws://127.0.0.1",
      brokerPubkey: broker.publicKeyBase64,
    });
    const daemon = await testDaemon(fixture);

    // Slow persistence: hold onBrokerPubkey open until the forward below has
    // been sent into the tunnel.
    let releasePersist: (() => void) | undefined;
    const persistGate = new Promise<void>((resolve) => {
      releasePersist = resolve;
    });
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: fixture.url,
      localPort: localApp.port,
      identity: daemon.identity,
      tls: clientTls(daemon, fixture),
      onBrokerPubkey: () => persistGate,
      log: silentLogger(),
    });
    const runPromise = client.run(ac.signal);

    // Registration happens broker-side at welcome time — the client is still
    // parked inside onBrokerPubkey here.
    await waitForRegistration(fixture, daemon.identity.uuid);
    const forwardPromise = fixture.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("mid-persist"),
    );
    // Give the frame time to traverse the tunnel while persistence is held.
    await new Promise((r) => setImmediate(r));
    releasePersist?.();

    const resp = await forwardPromise;
    expect(resp.status).toBe(200);
    expect(Buffer.from(resp.body, "base64").toString("utf8")).toBe("echo:mid-persist");

    ac.abort();
    await runPromise.catch(() => undefined);
    await fixture.close();
    await localApp.close();
  }, 10_000);

  it("dial timeout aborts cleanly and backs off — no unhandled 'error' crash", async () => {
    // A TCP server that accepts the connection but never completes the TLS
    // handshake, so the dial hangs until dialTimeoutMs fires. terminate() on a
    // still-CONNECTING socket emits 'error' on the next tick; if that isn't
    // swallowed it becomes an uncaughtException instead of a backoff.
    const conns = new Set<Socket>();
    const stuck = createNetServer((sock) => {
      // accept + hold the socket; never speak TLS/HTTP/WS
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
    const cert = await id.mintClientCert();
    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: `wss://127.0.0.1:${String(stuckPort)}/`,
      localPort: 1,
      identity: id,
      tls: { certPem: cert.certPem, keyPem: cert.keyPem },
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
    const localApp = await startLocalEcho();
    const broker = ephemeralBrokerKey();
    const fixture = await startMtlsRelay({
      baseUrl: "ws://127.0.0.1",
      brokerPubkey: broker.publicKeyBase64,
    });
    const daemon = await testDaemon(fixture);

    const ac = new AbortController();
    const client = new RelayClient({
      serverURL: fixture.url,
      localPort: localApp.port,
      identity: daemon.identity,
      tls: clientTls(daemon, fixture),
      log: silentLogger(),
      dialTimeoutMs: 150,
    });
    const runPromise = client.run(ac.signal);

    await waitForRegistration(fixture, daemon.identity.uuid);
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    // Wait well past the 150ms dial timeout — a stale timer would kill it here.
    await new Promise((r) => setTimeout(r, 500));
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(true);

    const resp = await fixture.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      { "Content-Type": ["text/plain"] },
      Buffer.from("hello"),
    );
    expect(resp.status).toBe(200);
    expect(localApp.received()).toBe("hello");

    ac.abort();
    await runPromise.catch(() => undefined);
    await fixture.close();
    await localApp.close();
  }, 10_000);
});
