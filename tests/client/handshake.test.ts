import { describe, expect, it } from "vitest";
import { create, toJson } from "@bufbuild/protobuf";
import { ServerMessageSchema } from "../../src/relay/pb/relay_pb.js";
import { Identity } from "../../src/client/identity.js";
import { runHandshake, type SocketLike } from "../../src/client/handshake.js";

class MockSocket implements SocketLike {
  sent: string[] = [];
  private pending: ((s: string) => void)[] = [];
  private inbox: string[] = [];
  send(s: string): void {
    this.sent.push(s);
  }
  recv(): Promise<string> {
    return new Promise((r) => {
      const queued = this.inbox.shift();
      if (queued !== undefined) r(queued);
      else this.pending.push(r);
    });
  }
  inject(s: string): void {
    const next = this.pending.shift();
    if (next) next(s);
    else this.inbox.push(s);
  }
}

function welcomeJson(opts: { url: string; brokerPubkey?: string; protocol?: number }): string {
  const env = create(ServerMessageSchema, {
    kind: {
      case: "welcome",
      value: {
        url: opts.url,
        ...(opts.protocol !== undefined ? { protocol: opts.protocol } : {}),
        ...(opts.brokerPubkey !== undefined ? { brokerPubkey: opts.brokerPubkey } : {}),
      },
    },
  });
  return JSON.stringify(toJson(ServerMessageSchema, env, { useProtoFieldName: true }));
}

function errorJson(message: string): string {
  const env = create(ServerMessageSchema, { kind: { case: "error", value: { message } } });
  return JSON.stringify(toJson(ServerMessageSchema, env, { useProtoFieldName: true }));
}

describe("runHandshake (v4)", () => {
  it("sends hello first — before any server frame — with only decrypt_pubkey (snake_case)", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    // The client speaks first: hello must already be on the wire before we
    // inject anything.
    expect(ws.sent).toHaveLength(1);
    const firstSent = ws.sent[0];
    if (firstSent === undefined) throw new Error("no message sent");
    const sent = JSON.parse(firstSent) as { hello: Record<string, unknown> };
    expect(Object.keys(sent)).toEqual(["hello"]);
    expect(sent.hello).toEqual({ decrypt_pubkey: id.decryptPubkeyB64 });

    ws.inject(
      welcomeJson({
        url: `wss://relay.example/u/${id.uuid}/hooks/`,
        brokerPubkey: "BROKERPK",
        protocol: 4,
      }),
    );

    const result = await p;
    expect(result.hookBaseURL).toBe(`wss://relay.example/u/${id.uuid}/hooks/`);
    expect(result.brokerPubkey).toBe("BROKERPK");
    expect(ws.sent).toHaveLength(1);
  });

  it("returns empty brokerPubkey when the welcome does not announce one", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    ws.inject(welcomeJson({ url: `wss://relay.example/u/${id.uuid}/hooks/`, protocol: 4 }));

    const result = await p;
    expect(result.brokerPubkey).toBe("");
  });

  it("propagates error envelope as exception", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    ws.inject(errorJson("client certificate required"));

    await expect(p).rejects.toThrow(/client certificate required/);
  });

  it("rejects a broker advertising protocol 3 as too old", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    ws.inject(welcomeJson({ url: `wss://x/u/${id.uuid}/hooks/`, protocol: 3 }));

    await expect(p).rejects.toThrow(/protocol 3 too old/);
  });

  it("rejects a welcome without a protocol field as too old", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    ws.inject(welcomeJson({ url: `wss://x/u/${id.uuid}/hooks/` }));

    await expect(p).rejects.toThrow(/protocol 0 too old/);
  });

  it("rejects when the welcome URL does not contain our uuid (cert/identity desync)", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    ws.inject(welcomeJson({ url: `wss://relay.example/u/${"0".repeat(64)}/hooks/`, protocol: 4 }));

    await expect(p).rejects.toThrow(/out of sync/);
  });

  it("detects a legacy v3 challenge first frame and names the broker version", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    // A v3 broker's first frame — the field is reserved in the v4 schema, so
    // this is hand-built JSON rather than a generated envelope.
    ws.inject(JSON.stringify({ challenge: { nonce: "00".repeat(32) } }));

    await expect(p).rejects.toThrow(/dicode-relay < 0\.2\.0/);
  });

  it("rejects an unexpected frame kind after hello", async () => {
    const ws = new MockSocket();
    const id = await Identity.generate();

    const p = runHandshake(ws, id);
    const env = create(ServerMessageSchema, {
      kind: {
        case: "request",
        value: { id: "r1", method: "GET", path: "/hooks/x", headers: {}, body: "" },
      },
    });
    ws.inject(JSON.stringify(toJson(ServerMessageSchema, env, { useProtoFieldName: true })));

    await expect(p).rejects.toThrow(/unexpected request/);
  });
});
