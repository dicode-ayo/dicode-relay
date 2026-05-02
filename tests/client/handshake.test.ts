import { describe, expect, it } from "vitest";
import { create, toJson } from "@bufbuild/protobuf";
import { ServerMessageSchema } from "../../src/relay/pb/relay_pb.js";
import { Identity } from "../../src/client/identity.js";
import { MemoryKv } from "../../src/client/kv-adapter.js";
import { TofuStore } from "../../src/client/tofu.js";
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

function challengeJson(nonceHex: string): string {
  const env = create(ServerMessageSchema, {
    kind: { case: "challenge", value: { nonce: nonceHex } },
  });
  return JSON.stringify(toJson(ServerMessageSchema, env, { useProtoFieldName: true }));
}

function welcomeJson(opts: { url: string; brokerPubkey?: string; protocol?: number }): string {
  const env = create(ServerMessageSchema, {
    kind: {
      case: "welcome",
      value: {
        url: opts.url,
        protocol: opts.protocol ?? 3,
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

describe("runHandshake", () => {
  it("sends hello after challenge, returns welcome url + brokerPubkey", async () => {
    const ws = new MockSocket();
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const tofu = new TofuStore(new MemoryKv());

    const p = runHandshake(ws, id, tofu);
    ws.inject(challengeJson("00".repeat(32)));
    // Yield once so the handshake can send hello before we inject welcome.
    await Promise.resolve();
    ws.inject(
      welcomeJson({
        url: `wss://relay.example/u/${id.uuid}/hooks/`,
        brokerPubkey: "BROKERPK",
        protocol: 3,
      }),
    );

    const result = await p;
    expect(result.hookBaseURL).toBe(`wss://relay.example/u/${id.uuid}/hooks/`);
    expect(result.brokerPubkey).toBe("BROKERPK");
    expect(ws.sent).toHaveLength(1);
    // Sanity-check the hello looks right — wire must be snake_case.
    const firstSent = ws.sent[0];
    if (firstSent === undefined) throw new Error("no message sent");
    const sent = JSON.parse(firstSent) as {
      hello: {
        uuid: string;
        pubkey: string;
        decrypt_pubkey: string;
        sig: string;
        timestamp: number;
      };
    };
    expect(sent.hello.uuid).toBe(id.uuid);
    expect(sent.hello.pubkey).toBe(id.signPubkeyB64);
    expect(sent.hello.decrypt_pubkey).toBe(id.decryptPubkeyB64);
    expect(typeof sent.hello.sig).toBe("string");
  });

  it("rejects on TOFU mismatch", async () => {
    const ws = new MockSocket();
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const kv = new MemoryKv();
    await kv.set("tofu.broker_pubkey", "ORIGINAL_KEY");
    const tofu = new TofuStore(kv);

    const p = runHandshake(ws, id, tofu);
    ws.inject(challengeJson("00".repeat(32)));
    await Promise.resolve();
    ws.inject(welcomeJson({ url: "wss://x", brokerPubkey: "DIFFERENT", protocol: 3 }));

    await expect(p).rejects.toThrow(/broker pubkey changed/);
  });

  it("rejects when broker protocol < 3", async () => {
    const ws = new MockSocket();
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const tofu = new TofuStore(new MemoryKv());

    const p = runHandshake(ws, id, tofu);
    ws.inject(challengeJson("00".repeat(32)));
    await Promise.resolve();
    ws.inject(welcomeJson({ url: "wss://x", protocol: 2 }));

    await expect(p).rejects.toThrow(/protocol/);
  });

  it("propagates error envelope as exception", async () => {
    const ws = new MockSocket();
    const id = await Identity.loadOrGenerate(new MemoryKv());
    const tofu = new TofuStore(new MemoryKv());

    const p = runHandshake(ws, id, tofu);
    ws.inject(challengeJson("00".repeat(32)));
    await Promise.resolve();
    ws.inject(errorJson("invalid signature"));

    await expect(p).rejects.toThrow(/invalid signature/);
  });
});
