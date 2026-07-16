import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startMtlsRelay, testDaemon, connectDaemon, type MtlsRelayFixture } from "../helpers.js";

describe("RelayServer events", () => {
  let fixture: MtlsRelayFixture;

  beforeEach(async () => {
    fixture = await startMtlsRelay();
  });

  afterEach(async () => {
    await fixture.close();
  });

  it("emits client:connected on successful handshake", async () => {
    const daemon = await testDaemon(fixture);
    const connected = new Promise<string>((resolve) => {
      fixture.relay.once("client:connected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const { ws } = await connectDaemon(fixture, daemon);

    const uuid = await connected;
    expect(uuid).toBe(daemon.identity.uuid);
    ws.terminate();
  });

  it("emits client:disconnected when client closes connection", async () => {
    const daemon = await testDaemon(fixture);
    const disconnected = new Promise<string>((resolve) => {
      fixture.relay.once("client:disconnected", (uuid: string) => {
        resolve(uuid);
      });
    });

    const { ws } = await connectDaemon(fixture, daemon);
    ws.close();

    const uuid = await disconnected;
    expect(uuid).toBe(daemon.identity.uuid);
    expect(fixture.relay.hasClient(daemon.identity.uuid)).toBe(false);
  });
});
