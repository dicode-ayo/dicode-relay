/**
 * Relay forwarding tests — real mTLS connections, no mocks.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BackpressureError,
  ClientNotConnectedError,
  ForwardTimeoutError,
  PendingCapExceededError,
} from "../../src/relay/server.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseRequest,
  responseEnvelope,
  type MtlsRelayFixture,
} from "../helpers.js";

describe("Relay forwarding", () => {
  let fixture: MtlsRelayFixture;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://relay.dicode.app" });
  });

  afterEach(async () => {
    await fixture.close();
  });

  it("forward() sends request message to correct WebSocket client", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    const receivedMessages: { id: string; method: string; path: string; body: string }[] = [];
    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req === null) return;
      receivedMessages.push(req);
      ws.send(
        responseEnvelope({
          id: req.id,
          status: 200,
          headers: { "Content-Type": ["application/json"] },
          body: Buffer.from(JSON.stringify({ ok: true })).toString("base64"),
        }),
      );
    });

    const result = await fixture.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/oauth-complete",
      { "Content-Type": ["application/json"] },
      Buffer.from(JSON.stringify({ test: "payload" })),
    );

    expect(result.status).toBe(200);
    expect(receivedMessages).toHaveLength(1);
    expect(receivedMessages[0]?.path).toBe("/hooks/oauth-complete");
    expect(receivedMessages[0]?.method).toBe("POST");

    ws.terminate();
  });

  it("client sends response, forward() resolves with response body", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req === null) return;
      ws.send(
        responseEnvelope({
          id: req.id,
          status: 201,
          body: Buffer.from("created").toString("base64"),
        }),
      );
    });

    const result = await fixture.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      {},
      Buffer.from("body"),
    );

    expect(result.status).toBe(201);
    expect(Buffer.from(result.body, "base64").toString()).toBe("created");

    ws.terminate();
  });

  it("forward() carries a query-bearing path verbatim", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req === null) return;
      ws.send(
        responseEnvelope({
          id: req.id,
          status: 200,
          body: Buffer.from(req.path).toString("base64"),
        }),
      );
    });

    const path = "/hooks/task?wait=false&name=a%20b%26c";
    const result = await fixture.relay.forward(
      daemon.identity.uuid,
      "GET",
      path,
      {},
      Buffer.alloc(0),
    );

    expect(Buffer.from(result.body, "base64").toString()).toBe(path);

    ws.terminate();
  });

  it("forward to unknown UUID throws ClientNotConnectedError", async () => {
    await expect(
      fixture.relay.forward("a".repeat(64), "GET", "/", {}, Buffer.alloc(0)),
    ).rejects.toThrow(ClientNotConnectedError);
  });

  it("forward to unknown UUID throws error with correct name", async () => {
    await expect(
      fixture.relay.forward("b".repeat(64), "GET", "/", {}, Buffer.alloc(0)),
    ).rejects.toThrow("Client not connected");
  });

  it("ForwardTimeoutError has correct name", () => {
    const err = new ForwardTimeoutError("test-id");
    expect(err.name).toBe("ForwardTimeoutError");
    expect(err.message).toContain("test-id");
  });

  it("ClientNotConnectedError has correct name", () => {
    const err = new ClientNotConnectedError("some-uuid");
    expect(err.name).toBe("ClientNotConnectedError");
    expect(err.message).toContain("some-uuid");
  });

  it("server.close() rejects pending forward promises", async () => {
    // Separate fixture so closing it does not interfere with afterEach.
    const temp = await startMtlsRelay({ baseUrl: "wss://test.local" });
    const daemon = await testDaemon(temp);
    await connectDaemon(temp, daemon);

    // Don't handle messages — let it hang.
    const forwardPromise = temp.relay.forward(
      daemon.identity.uuid,
      "POST",
      "/hooks/test",
      {},
      Buffer.from("body"),
    );

    const closing = temp.close();
    await expect(forwardPromise).rejects.toThrow("Server closing");
    await closing;
  });

  it("rejects at the per-daemon pending cap and recovers as forwards drain", async () => {
    const temp = await startMtlsRelay({ baseUrl: "wss://test.local", maxPendingPerClient: 2 });
    try {
      const daemon = await testDaemon(temp);
      const { ws } = await connectDaemon(temp, daemon);

      // Record the ids the daemon receives but don't auto-respond — the test
      // drains specific requests by id to exercise cap recovery.
      const ids: string[] = [];
      ws.on("message", (data: Buffer | string) => {
        const req = parseRequest(data);
        if (req !== null) ids.push(req.id);
      });
      const drain = (i: number): void => {
        const id = ids[i];
        if (id === undefined) throw new Error(`no request received at index ${String(i)}`);
        ws.send(responseEnvelope({ id, status: 200, body: "" }));
      };

      // Two in-flight forwards fill the cap (no responses → they stay pending).
      const p1 = temp.relay.forward(daemon.identity.uuid, "POST", "/hooks/a", {}, Buffer.alloc(0));
      const p2 = temp.relay.forward(daemon.identity.uuid, "POST", "/hooks/b", {}, Buffer.alloc(0));

      // Third forward exceeds the cap → rejected, and never reaches the daemon.
      await expect(
        temp.relay.forward(daemon.identity.uuid, "POST", "/hooks/c", {}, Buffer.alloc(0)),
      ).rejects.toThrow(PendingCapExceededError);
      await vi.waitFor(() => {
        expect(ids).toHaveLength(2);
      });

      // Drain one → outstanding count drops below the cap.
      drain(0);
      await p1;

      // A fresh forward now fits under the cap and completes.
      const p3 = temp.relay.forward(daemon.identity.uuid, "POST", "/hooks/d", {}, Buffer.alloc(0));
      await vi.waitFor(() => {
        expect(ids).toHaveLength(3);
      });
      drain(2);
      expect((await p3).status).toBe(200);

      // Drain the remaining in-flight forward so close() has nothing pending.
      drain(1);
      await p2;

      ws.terminate();
    } finally {
      await temp.close();
    }
  });

  it("rejects with BackpressureError when the socket send buffer is over threshold", async () => {
    const temp = await startMtlsRelay({ baseUrl: "wss://test.local", maxBufferedBytes: 1000 });
    try {
      const daemon = await testDaemon(temp);
      await connectDaemon(temp, daemon);

      // Stub the server-side socket's bufferedAmount above the threshold — an
      // own property shadows ws's prototype getter.
      const client = temp.relay.getClient(daemon.identity.uuid);
      Object.defineProperty(client.ws, "bufferedAmount", {
        configurable: true,
        get: () => 2000,
      });

      await expect(
        temp.relay.forward(daemon.identity.uuid, "POST", "/hooks/x", {}, Buffer.alloc(0)),
      ).rejects.toThrow(BackpressureError);
    } finally {
      await temp.close();
    }
  });

  it("concurrent forwards to same client both resolve", async () => {
    const daemon = await testDaemon(fixture);
    const { ws } = await connectDaemon(fixture, daemon);

    ws.on("message", (data: Buffer | string) => {
      const req = parseRequest(data);
      if (req === null) return;
      // Respond asynchronously to test concurrency
      setTimeout(() => {
        ws.send(
          responseEnvelope({
            id: req.id,
            status: 200,
            body: Buffer.from(req.path).toString("base64"),
          }),
        );
      }, 10);
    });

    const [r1, r2] = await Promise.all([
      fixture.relay.forward(daemon.identity.uuid, "GET", "/path1", {}, Buffer.alloc(0)),
      fixture.relay.forward(daemon.identity.uuid, "GET", "/path2", {}, Buffer.alloc(0)),
    ]);

    expect(Buffer.from(r1.body, "base64").toString()).toBe("/path1");
    expect(Buffer.from(r2.body, "base64").toString()).toBe("/path2");

    ws.terminate();
  });
});
