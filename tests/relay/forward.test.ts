/**
 * Relay forwarding tests — real mTLS connections, no mocks.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ClientNotConnectedError, ForwardTimeoutError } from "../../src/relay/server.js";
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
