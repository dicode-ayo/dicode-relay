/**
 * RelayServer — WebSocket server implementing the dicode relay protocol.
 *
 * The wire schema is generated from `proto/relay.proto` via `buf generate`
 * (see ./pb/relay_pb.ts). On the wire: JSON text frames whose shape matches
 * what `@bufbuild/protobuf`'s fromJson/toJson produces for the generated
 * ServerMessage and ClientMessage oneof envelopes.
 *
 * Responsibilities:
 *  - Challenge/response handshake with ECDSA P-256 signature verification
 *  - Connected-client registry (uuid → WebSocket + public key)
 *  - HTTP request forwarding to daemon over the established WebSocket
 *  - Ping/pong keepalive (30 s interval, 10 s timeout)
 */

import { createHash, createPublicKey, createVerify } from "node:crypto";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import { type Server } from "node:http";
import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import { WebSocket, WebSocketServer } from "ws";
import { v4 as uuidv4 } from "uuid";
import { NonceStore } from "./nonces.js";
import {
  ClientMessageSchema,
  HeaderValuesSchema,
  RequestSchema,
  ServerMessageSchema,
  type ClientMessage,
  type Hello,
  type Response as ResponseMessage,
  type ServerMessage,
} from "./pb/relay_pb.js";
import type { ForwardResponse } from "./protocol.js";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

export class ClientNotConnectedError extends Error {
  constructor(uuid: string) {
    super(`Client not connected: ${uuid}`);
    this.name = "ClientNotConnectedError";
  }
}

export class ForwardTimeoutError extends Error {
  constructor(id: string) {
    super(`Request timed out: ${id}`);
    this.name = "ForwardTimeoutError";
  }
}

/**
 * Broker protocol version advertised in the welcome message.
 * Version 3 (dicode-core#195) means: generated-from-proto wire format.
 *   - headers: map<string, HeaderValues{values: repeated string}>
 *   - timestamp: int32 (so the JSON encoding is a number, not a quoted string)
 *   - envelope: {"<kind>": {...}} instead of flat {"type": "...", ...}
 * Daemons refuse connections when the broker advertises < 3.
 */
export const PROTOCOL_VERSION = 3;

// ---------------------------------------------------------------------------
// Client registry entry
// ---------------------------------------------------------------------------

export interface ConnectedClient {
  ws: WebSocket;
  uuid: string;
  /** 65-byte uncompressed P-256 public key (0x04 || X || Y). Used for ECDSA
   *  signature verification (WSS handshake + /auth/:provider sigs). */
  pubkey: Buffer;
  /** 65-byte uncompressed P-256 public key used by the broker as the ECIES
   *  recipient when encrypting OAuth token deliveries (dicode-core#104). */
  decryptPubkey: Buffer;
}

// ---------------------------------------------------------------------------
// Pending forward request
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (response: ForwardResponse) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ---------------------------------------------------------------------------
// RelayServer
// ---------------------------------------------------------------------------

export interface RelayServerOptions {
  /** Public base URL, e.g. "wss://relay.dicode.app" — used in welcome message */
  baseUrl: string;
  /** HTTP(S) server to attach the WebSocket server to (optional) */
  server?: Server;
  /** Port to listen on when no server is provided */
  port?: number;
  /** All tuning values — sourced from the Zod config schema (config.ts) */
  timestampToleranceS: number;
  pingIntervalMs: number;
  pongTimeoutMs: number;
  requestTimeoutMs: number;
  nonceTtlMs: number;
  /** Base64-encoded SPKI DER public key for broker delivery signing. Announced in the welcome message. */
  brokerPubkey?: string;
}

export class RelayServer extends EventEmitter {
  private readonly wss: WebSocketServer;
  private readonly nonces: NonceStore;
  private readonly clients = new Map<string, ConnectedClient>();
  private readonly pending = new Map<string, PendingRequest>();
  private readonly baseUrl: string;
  private readonly timestampToleranceS: number;
  private readonly pingIntervalMs: number;
  private readonly pongTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly brokerPubkey: string | undefined;

  constructor(opts: RelayServerOptions) {
    super();
    this.baseUrl = opts.baseUrl;
    this.nonces = new NonceStore(opts.nonceTtlMs);
    this.timestampToleranceS = opts.timestampToleranceS;
    this.pingIntervalMs = opts.pingIntervalMs;
    this.pongTimeoutMs = opts.pongTimeoutMs;
    this.requestTimeoutMs = opts.requestTimeoutMs;
    this.brokerPubkey = opts.brokerPubkey;

    if (opts.server !== undefined) {
      this.wss = new WebSocketServer({ server: opts.server });
    } else if (opts.port !== undefined) {
      this.wss = new WebSocketServer({ port: opts.port });
    } else {
      // Random available port (useful for tests)
      this.wss = new WebSocketServer({ port: 0 });
    }

    this.wss.on("connection", (ws: WebSocket, _req: IncomingMessage) => {
      this.handleConnection(ws);
    });
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  get port(): number {
    const addr = this.wss.address();
    if (typeof addr === "string" || addr === null) {
      throw new Error("Server address unavailable");
    }
    return addr.port;
  }

  getClient(uuid: string): ConnectedClient {
    const client = this.clients.get(uuid);
    if (client === undefined) {
      throw new ClientNotConnectedError(uuid);
    }
    return client;
  }

  hasClient(uuid: string): boolean {
    return this.clients.has(uuid);
  }

  /**
   * Forward an HTTP-style request to the daemon identified by `uuid`.
   * Rejects with ForwardTimeoutError after the configured timeout or
   * ClientNotConnectedError if the daemon is not connected.
   */
  async forward(
    uuid: string,
    method: string,
    path: string,
    headers: Record<string, string[]>,
    body: Buffer,
  ): Promise<ForwardResponse> {
    const client = this.getClient(uuid);
    const id = uuidv4();

    // Build the generated Request. Headers map entries wrap their string
    // arrays in HeaderValues (proto3 maps cannot hold repeated values).
    const wireHeaders: Record<string, ReturnType<typeof create<typeof HeaderValuesSchema>>> = {};
    for (const [k, values] of Object.entries(headers)) {
      wireHeaders[k] = create(HeaderValuesSchema, { values });
    }
    const request = create(RequestSchema, {
      id,
      method,
      path,
      headers: wireHeaders,
      body: body.toString("base64"),
    });
    const envelope = create(ServerMessageSchema, {
      kind: { case: "request", value: request },
    });

    return new Promise<ForwardResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new ForwardTimeoutError(id));
      }, this.requestTimeoutMs);
      timer.unref();

      this.pending.set(id, { resolve, reject, timer });
      this.sendServerMessage(client.ws, envelope);
    });
  }

  close(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      for (const [id, pending] of this.pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("Server closing"));
        this.pending.delete(id);
      }

      for (const client of this.clients.values()) {
        client.ws.terminate();
      }
      this.clients.clear();
      this.nonces.clear();

      this.wss.close((err) => {
        if (err !== undefined) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Connection lifecycle
  // ---------------------------------------------------------------------------

  private handleConnection(ws: WebSocket): void {
    // Send challenge immediately.
    const nonce = randomBytes(32).toString("hex"); // 64 hex chars
    const challengeEnvelope = create(ServerMessageSchema, {
      kind: { case: "challenge", value: { nonce } },
    });
    this.sendServerMessage(ws, challengeEnvelope);

    let registeredUuid: string | null = null;
    let pingTimer: ReturnType<typeof setInterval> | null = null;
    let pongTimer: ReturnType<typeof setTimeout> | null = null;

    const cleanup = (): void => {
      if (pingTimer !== null) {
        clearInterval(pingTimer);
        pingTimer = null;
      }
      if (pongTimer !== null) {
        clearTimeout(pongTimer);
        pongTimer = null;
      }
      if (registeredUuid !== null) {
        this.emit("client:disconnected", registeredUuid);
        this.clients.delete(registeredUuid);
        registeredUuid = null;
      }
    };

    ws.on("message", (data: Buffer | string) => {
      const raw = typeof data === "string" ? data : data.toString("utf8");
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw) as unknown;
      } catch {
        this.sendError(ws, "invalid JSON");
        ws.close();
        return;
      }

      let envelope: ClientMessage;
      try {
        envelope = fromJson(ClientMessageSchema, parsed as JsonValue, {
          ignoreUnknownFields: true,
        });
      } catch {
        if (registeredUuid === null) {
          this.sendError(ws, "expected hello message");
          ws.close();
        }
        // After registration we silently drop malformed frames — same as the
        // pre-proto behavior when ResponseMessageSchema.safeParse failed.
        return;
      }

      if (registeredUuid === null) {
        // Expecting a hello message.
        if (envelope.kind.case !== "hello") {
          this.sendError(ws, "expected hello message");
          ws.close();
          return;
        }
        const hello = envelope.kind.value;
        const err = this.verifyHello(hello, nonce);
        if (err !== null) {
          this.sendError(ws, err);
          ws.close();
          return;
        }

        const pubkeyBytes = Buffer.from(hello.pubkey, "base64");
        const decryptPubkeyBytes = Buffer.from(hello.decryptPubkey, "base64");

        this.clients.set(hello.uuid, {
          ws,
          uuid: hello.uuid,
          pubkey: pubkeyBytes,
          decryptPubkey: decryptPubkeyBytes,
        });
        registeredUuid = hello.uuid;

        const welcomeEnvelope = create(ServerMessageSchema, {
          kind: {
            case: "welcome",
            value: {
              url: `${this.baseUrl}/u/${hello.uuid}/hooks/`,
              protocol: PROTOCOL_VERSION,
              ...(this.brokerPubkey !== undefined ? { brokerPubkey: this.brokerPubkey } : {}),
            },
          },
        });
        this.sendServerMessage(ws, welcomeEnvelope);
        this.emit("client:connected", hello.uuid);

        // Start keepalive.
        pingTimer = setInterval(() => {
          if (ws.readyState !== WebSocket.OPEN) {
            cleanup();
            return;
          }
          ws.ping();
          pongTimer = setTimeout(() => {
            ws.terminate();
            cleanup();
          }, this.pongTimeoutMs);
          pongTimer.unref();
        }, this.pingIntervalMs);
        pingTimer.unref();

        return;
      }

      // Post-registration: expect a response.
      if (envelope.kind.case !== "response") {
        // Silently ignore non-response frames after registration.
        return;
      }
      const response = envelope.kind.value;
      // HTTP status sanity check — previously enforced by a Zod range (100–599),
      // lost in the proto migration because proto3 int32 has no range. A rogue
      // daemon emitting an out-of-range status could confuse the relay's HTTP
      // caller. Drop rather than forward.
      if (response.status < 100 || response.status > 599) {
        return;
      }
      const req = this.pending.get(response.id);
      if (req !== undefined) {
        clearTimeout(req.timer);
        this.pending.delete(response.id);
        req.resolve(this.flattenResponse(response));
      }
    });

    ws.on("pong", () => {
      if (pongTimer !== null) {
        clearTimeout(pongTimer);
        pongTimer = null;
      }
    });

    ws.on("close", () => {
      cleanup();
    });

    ws.on("error", () => {
      cleanup();
    });
  }

  // ---------------------------------------------------------------------------
  // Handshake verification
  // ---------------------------------------------------------------------------

  /**
   * Verifies all fields of a hello message.
   * Returns null on success, or an error string on failure.
   */
  private verifyHello(hello: Hello, nonce: string): string | null {
    // Step 1: Decode pubkey — must be exactly 65 bytes starting with 0x04.
    let pubkeyBytes: Buffer;
    try {
      pubkeyBytes = Buffer.from(hello.pubkey, "base64");
    } catch {
      return "invalid pubkey encoding";
    }
    if (pubkeyBytes.length !== 65 || pubkeyBytes[0] !== 0x04) {
      return "pubkey must be 65 bytes starting with 0x04";
    }

    // Step 1b: Validate decrypt_pubkey structurally and as an on-curve P-256
    // point (dicode-core#104). Required — every daemon advertises a split
    // sign/decrypt identity. Parse failures reject the handshake.
    if (hello.decryptPubkey === "") {
      return "decrypt_pubkey is required";
    }
    let decryptBytes: Buffer;
    try {
      decryptBytes = Buffer.from(hello.decryptPubkey, "base64");
    } catch {
      return "invalid decrypt_pubkey encoding";
    }
    if (decryptBytes.length !== 65 || decryptBytes[0] !== 0x04) {
      return "decrypt_pubkey must be 65 bytes starting with 0x04";
    }
    try {
      const spkiDer = uncompressedP256ToSpki(decryptBytes);
      createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    } catch {
      return "decrypt_pubkey is not a valid P-256 point";
    }

    // Step 2: Verify uuid == hex(sha256(pubkey)).
    const expectedUuid = createHash("sha256").update(pubkeyBytes).digest("hex");
    if (expectedUuid !== hello.uuid) {
      return "uuid does not match sha256(pubkey)";
    }

    // Step 3: Verify timestamp within ±timestampToleranceS.
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - hello.timestamp) > this.timestampToleranceS) {
      return "timestamp out of range";
    }

    // Step 4: Verify nonce not seen in last nonceTtlMs.
    if (this.nonces.check(nonce)) {
      return "nonce replayed";
    }

    // Step 5: Verify ECDSA signature over sha256(nonce_bytes || timestamp_be_uint64).
    // The Go client signs the raw sha256 digest with ecdsa.SignASN1 over an
    // 8-byte big-endian timestamp — the wire int32 is widened back here so
    // the preimage matches regardless of the smaller wire encoding.
    const nonceBytes = Buffer.from(nonce, "hex");
    const tsBytes = Buffer.allocUnsafe(8);
    tsBytes.writeBigUInt64BE(BigInt(hello.timestamp));
    const message = Buffer.concat([nonceBytes, tsBytes]);

    try {
      const verify = createVerify("SHA256");
      verify.update(message);
      const spkiDer = uncompressedP256ToSpki(pubkeyBytes);
      const valid = verify.verify(
        { key: spkiDer, format: "der", type: "spki" },
        Buffer.from(hello.sig, "base64"),
      );
      if (!valid) {
        return "invalid signature";
      }
    } catch {
      return "signature verification failed";
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private sendServerMessage(ws: WebSocket, msg: ServerMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(toJson(ServerMessageSchema, msg)));
    }
  }

  private sendError(ws: WebSocket, message: string): void {
    const envelope = create(ServerMessageSchema, {
      kind: { case: "error", value: { message } },
    });
    this.sendServerMessage(ws, envelope);
  }

  private flattenResponse(resp: ResponseMessage): ForwardResponse {
    const headers: Record<string, string[]> = {};
    // resp.headers is typed as Record<string, HeaderValues>; Object.entries
    // returns [string, unknown][] under noUncheckedIndexedAccess, so we access
    // it back through the typed record.
    for (const k of Object.keys(resp.headers)) {
      const hv = resp.headers[k];
      if (hv !== undefined) {
        headers[k] = hv.values;
      }
    }
    return { status: resp.status, headers, body: resp.body };
  }
}

// ---------------------------------------------------------------------------
// DER encoding helper
// ---------------------------------------------------------------------------

/**
 * Wraps a raw 65-byte uncompressed P-256 public key into a DER-encoded
 * SubjectPublicKeyInfo structure so Node.js crypto can import it.
 */
function uncompressedP256ToSpki(pubkey: Buffer): Buffer {
  const header = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
  return Buffer.concat([header, pubkey]);
}

// Re-export generated types for tests and external consumers.
export type { Request, Response } from "./pb/relay_pb.js";
