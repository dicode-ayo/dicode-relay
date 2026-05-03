import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import { ClientMessageSchema, HelloSchema, ServerMessageSchema } from "../relay/pb/relay_pb.js";
import type { Identity } from "./identity.js";

const BROKER_PROTOCOL_MIN = 3;

export type TofuResult = "new" | "match" | "mismatch";

export interface SocketLike {
  send: (data: string) => void;
  recv: () => Promise<string>;
}

export interface HandshakeResult {
  hookBaseURL: string;
  brokerPubkey: string;
}

export async function runHandshake(
  ws: SocketLike,
  identity: Identity,
  tofuCheckAndPin: (brokerPubkeyB64: string) => Promise<TofuResult>,
): Promise<HandshakeResult> {
  // 1. Receive challenge.
  const challengeRaw = await ws.recv();
  const challengeEnv = fromJson(ServerMessageSchema, JSON.parse(challengeRaw) as JsonValue, {
    ignoreUnknownFields: true,
  });
  if (challengeEnv.kind.case !== "challenge") {
    throw new Error(`expected challenge, got ${String(challengeEnv.kind.case)}`);
  }
  const nonce = challengeEnv.kind.value.nonce;

  // 2. Sign + send hello.
  const ts = Math.floor(Date.now() / 1000);
  const sigB64 = await identity.signChallenge(nonce, ts);
  const hello = create(HelloSchema, {
    uuid: identity.uuid,
    pubkey: identity.signPubkeyB64,
    decryptPubkey: identity.decryptPubkeyB64,
    sig: sigB64,
    timestamp: ts,
  });
  const helloEnv = create(ClientMessageSchema, { kind: { case: "hello", value: hello } });
  // useProtoFieldName: true emits snake_case on the wire (e.g. "decrypt_pubkey").
  // Matches the Go relay server's UseProtoNames:true output. The TS server's
  // fromJson accepts both forms via @bufbuild/protobuf's tolerant decoder.
  ws.send(JSON.stringify(toJson(ClientMessageSchema, helloEnv, { useProtoFieldName: true })));

  // 3. Receive welcome (or error).
  const welcomeRaw = await ws.recv();
  const welcomeEnv = fromJson(ServerMessageSchema, JSON.parse(welcomeRaw) as JsonValue, {
    ignoreUnknownFields: true,
  });

  if (welcomeEnv.kind.case === "error") {
    throw new Error(`relay rejected handshake: ${welcomeEnv.kind.value.message}`);
  }
  if (welcomeEnv.kind.case !== "welcome") {
    throw new Error(`unexpected ${String(welcomeEnv.kind.case)} after hello`);
  }
  const welcome = welcomeEnv.kind.value;

  if ((welcome.protocol ?? 0) < BROKER_PROTOCOL_MIN) {
    throw new Error(
      `broker protocol ${String(welcome.protocol ?? 0)} too old — require >= ${String(BROKER_PROTOCOL_MIN)}`,
    );
  }

  if (welcome.brokerPubkey) {
    const res = await tofuCheckAndPin(welcome.brokerPubkey);
    if (res === "mismatch") {
      throw new Error(
        "relay: broker pubkey changed — run `dicode relay trust-broker --yes` to accept the new key",
      );
    }
  }

  return {
    hookBaseURL: welcome.url,
    brokerPubkey: welcome.brokerPubkey ?? "",
  };
}
