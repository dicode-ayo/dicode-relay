import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import { ClientMessageSchema, HelloSchema, ServerMessageSchema } from "../relay/pb/relay_pb.js";
import type { Identity } from "./identity.js";

const BROKER_PROTOCOL_MIN = 4;

export interface SocketLike {
  send: (data: string) => void;
  recv: () => Promise<string>;
}

export interface HandshakeResult {
  hookBaseURL: string;
  brokerPubkey: string;
}

/**
 * v4 handshake. The daemon's identity already traveled in its TLS client
 * certificate; the application-level exchange is a single round-trip:
 * hello{decrypt_pubkey} → welcome{url, broker_pubkey, protocol}.
 */
export async function runHandshake(ws: SocketLike, identity: Identity): Promise<HandshakeResult> {
  // 1. Send hello. The client speaks first — there is no server challenge.
  const hello = create(HelloSchema, {
    decryptPubkey: identity.decryptPubkeyB64,
  });
  const helloEnv = create(ClientMessageSchema, { kind: { case: "hello", value: hello } });
  // useProtoFieldName: true emits snake_case on the wire (e.g. "decrypt_pubkey").
  ws.send(JSON.stringify(toJson(ClientMessageSchema, helloEnv, { useProtoFieldName: true })));

  // 2. Receive welcome (or error).
  const welcomeRaw = await ws.recv();
  const parsed = JSON.parse(welcomeRaw) as JsonValue;
  // A v3 broker's first frame is a challenge — surface a targeted error
  // instead of "unexpected undefined" (the field is reserved in v4 schemas).
  if (typeof parsed === "object" && parsed !== null && "challenge" in parsed) {
    throw new Error(
      "relay: broker sent a handshake challenge — it is running dicode-relay < 0.2.0, " +
        "which this client no longer supports. Upgrade the broker.",
    );
  }
  const welcomeEnv = fromJson(ServerMessageSchema, parsed, {
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

  // 3. Cross-check the URL's uuid against our identity. The broker derived
  // the uuid from our TLS client certificate; a mismatch means the presented
  // cert does not wrap this identity's sign key (cert/identity desync).
  if (!welcome.url.includes(`/u/${identity.uuid}/`)) {
    throw new Error(
      `relay: welcome URL does not contain our uuid — client certificate and identity are out of sync (url: ${welcome.url})`,
    );
  }

  return {
    hookBaseURL: welcome.url,
    brokerPubkey: welcome.brokerPubkey ?? "",
  };
}
