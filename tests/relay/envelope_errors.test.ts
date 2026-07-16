/**
 * Envelope-level error paths. Covers the branches that fire before a valid
 * hello registers the daemon, plus the status-code range guard on the
 * response side.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import { CLOSE_BAD_HELLO, ForwardTimeoutError } from "../../src/relay/server.js";
import {
  startMtlsRelay,
  testDaemon,
  connectDaemon,
  parseError,
  parseRequest,
  responseEnvelope,
  type MtlsRelayFixture,
  type TestDaemon,
} from "../helpers.js";

/**
 * Dial with the daemon's client cert, send `frame` once open, and resolve
 * with the first error message plus the close code.
 */
function sendFrameExpectClose(
  fixture: MtlsRelayFixture,
  daemon: TestDaemon,
  frame: string,
): Promise<{ code: number; errorMessage: string | null }> {
  const ws = new WebSocket(fixture.url, { agent: daemon.agent });
  return new Promise((resolve, reject) => {
    let errorMessage: string | null = null;
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new Error("close timeout"));
    }, 5000);
    ws.on("open", () => {
      ws.send(frame);
    });
    ws.on("message", (data: Buffer | string) => {
      const e = parseError(data);
      if (e !== null) errorMessage = e.message;
    });
    ws.on("close", (code: number) => {
      clearTimeout(timer);
      resolve({ code, errorMessage });
    });
    ws.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

describe("Envelope error paths", () => {
  let fixture: MtlsRelayFixture;
  let daemon: TestDaemon;

  beforeEach(async () => {
    fixture = await startMtlsRelay({ baseUrl: "wss://x" });
    daemon = await testDaemon(fixture);
  });

  afterEach(async () => {
    await fixture.close();
  });

  it("first message is a response envelope → error + close 4400 (wrong envelope variant before registration)", async () => {
    const { code, errorMessage } = await sendFrameExpectClose(
      fixture,
      daemon,
      JSON.stringify({
        response: { id: "00000000-0000-0000-0000-000000000000", status: 200, body: "" },
      }),
    );
    expect(errorMessage).toContain("hello");
    expect(code).toBe(CLOSE_BAD_HELLO);
  });

  it("envelope with an unknown variant key → error + close before registration", async () => {
    // Garbage shape — no valid envelope key. Parses to an empty oneof, which
    // is not a hello, so the pre-registration gate fires.
    const { code, errorMessage } = await sendFrameExpectClose(
      fixture,
      daemon,
      JSON.stringify({ nonsense: { foo: "bar" } }),
    );
    expect(errorMessage).toContain("hello");
    expect(code).toBe(CLOSE_BAD_HELLO);
  });

  it("response with out-of-range status is silently dropped (pending request times out)", async () => {
    // Register a daemon, then have it reply with status=50. The forward()
    // promise must reject with a timeout (the server drops the bogus status
    // rather than resolving with it).
    const short = await startMtlsRelay({ baseUrl: "wss://x", requestTimeoutMs: 200 });
    try {
      const shortDaemon = await testDaemon(short);
      const { ws } = await connectDaemon(short, shortDaemon);

      ws.on("message", (data: Buffer | string) => {
        const req = parseRequest(data);
        if (req === null) return;
        ws.send(responseEnvelope({ id: req.id, status: 50, body: "" }));
      });

      await expect(
        short.relay.forward(
          shortDaemon.identity.uuid,
          "GET",
          "/hooks/anything",
          {},
          Buffer.alloc(0),
        ),
      ).rejects.toThrow(ForwardTimeoutError);

      ws.terminate();
    } finally {
      await short.close();
    }
  });
});
