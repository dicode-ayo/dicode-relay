/**
 * RelayServer — WebSocket server implementing the dicode relay protocol.
 *
 * The wire schema is generated from `proto/relay.proto` via `buf generate`
 * (see ./pb/relay_pb.ts). On the wire: JSON text frames whose shape matches
 * what `@bufbuild/protobuf`'s fromJson/toJson produces for the generated
 * ServerMessage and ClientMessage oneof envelopes.
 *
 * The listener is mTLS: daemons authenticate with a self-signed TLS client
 * certificate wrapping their P-256 signing key. The certificate chain is not
 * CA-verified (`rejectUnauthorized: false`) — identity is the key itself,
 * uuid = hex(sha256(uncompressed_cert_pubkey)). TLS 1.3 CertificateVerify
 * channel-binds the key, so no application-level challenge is needed.
 *
 * Responsibilities:
 *  - Peer-certificate identity extraction + slim hello (ECIES recipient key)
 *  - Connected-client registry (uuid → WebSocket + public key)
 *  - HTTP request forwarding to daemon over the established WebSocket
 *  - Ping/pong keepalive (30 s interval, 10 s timeout)
 */

import { createPublicKey } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import type { Server as HttpsServer } from "node:https";
import type { TLSSocket } from "node:tls";
import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import { WebSocket, WebSocketServer } from "ws";
import { v4 as uuidv4 } from "uuid";
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
import { uncompressedP256ToSpki } from "../shared/crypto.js";
import { extractP256PointFromCert, uuidFromP256Point } from "../shared/certs.js";
import type { ForwardResponse } from "../shared/protocol.js";

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

/** Raised by forward() when a daemon already has the maximum number of
 *  outstanding forwards. The HTTP layer maps this to 429. */
export class PendingCapExceededError extends Error {
  constructor(uuid: string) {
    super(`Too many outstanding forwards for client: ${uuid}`);
    this.name = "PendingCapExceededError";
  }
}

/** Raised by forward() when a daemon socket's send buffer is above the
 *  backpressure threshold. The HTTP layer maps this to 503. */
export class BackpressureError extends Error {
  constructor(uuid: string) {
    super(`Client socket send buffer saturated: ${uuid}`);
    this.name = "BackpressureError";
  }
}

/**
 * Broker protocol version advertised in the welcome message.
 * Version 4 means: mTLS control channel — daemon identity travels in the TLS
 * client certificate; hello carries only the ECIES recipient key.
 * Daemons refuse connections when the broker advertises < 4.
 */
export const PROTOCOL_VERSION = 4;

/** WS close codes for mTLS admission failures. 4409 is reserved for a
 *  future tenancy admission gate. */
export const CLOSE_BAD_HELLO = 4400;
export const CLOSE_NO_CLIENT_CERT = 4401;
export const CLOSE_CERT_NOT_P256 = 4402;

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
   *  recipient when encrypting OAuth token deliveries. */
  decryptPubkey: Buffer;
}

// ---------------------------------------------------------------------------
// Pending forward request
// ---------------------------------------------------------------------------

interface PendingRequest {
  /** uuid of the daemon this forward was issued to — needed to decrement the
   *  per-client outstanding count when the entry is removed. */
  uuid: string;
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
  /**
   * The mTLS HTTPS server to attach the WebSocket server to. Must be created
   * with `requestCert: true, rejectUnauthorized: false` — the peer certificate
   * is the daemon's identity and connections without one are rejected at the
   * WS layer with CLOSE_NO_CLIENT_CERT.
   */
  server: HttpsServer;
  /** All tuning values — sourced from the Zod config schema (config.ts) */
  pingIntervalMs: number;
  pongTimeoutMs: number;
  requestTimeoutMs: number;
  /** Max outstanding forwards per daemon uuid before forward() rejects with
   *  PendingCapExceededError. */
  maxPendingPerClient: number;
  /** ws.bufferedAmount threshold (bytes) above which forward() rejects with
   *  BackpressureError instead of queueing onto a non-draining socket. */
  maxBufferedBytes: number;
  /** Base64-encoded SPKI DER public key for broker delivery signing. Announced in the welcome message. */
  brokerPubkey?: string;
}

export class RelayServer extends EventEmitter {
  private readonly wss: WebSocketServer;
  private readonly clients = new Map<string, ConnectedClient>();
  private readonly pending = new Map<string, PendingRequest>();
  /** Outstanding-forward count per daemon uuid. Kept in lockstep with `pending`
   *  through addPending/removePending; entries drop to nothing (deleted) at 0. */
  private readonly pendingByClient = new Map<string, number>();
  private readonly baseUrl: string;
  private readonly pingIntervalMs: number;
  private readonly pongTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly maxPendingPerClient: number;
  private readonly maxBufferedBytes: number;
  private readonly brokerPubkey: string | undefined;

  constructor(opts: RelayServerOptions) {
    super();
    this.baseUrl = opts.baseUrl;
    this.pingIntervalMs = opts.pingIntervalMs;
    this.pongTimeoutMs = opts.pongTimeoutMs;
    this.requestTimeoutMs = opts.requestTimeoutMs;
    this.maxPendingPerClient = opts.maxPendingPerClient;
    this.maxBufferedBytes = opts.maxBufferedBytes;
    this.brokerPubkey = opts.brokerPubkey;

    this.wss = new WebSocketServer({ server: opts.server });

    this.wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
      this.handleConnection(ws, req);
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

    // Backpressure: refuse to enqueue onto a socket that is not draining.
    // Checked before the pending cap so a stuck-but-idle socket sheds load
    // immediately rather than filling the pending map first.
    if (client.ws.bufferedAmount > this.maxBufferedBytes) {
      throw new BackpressureError(uuid);
    }

    // Per-daemon outstanding-forward cap — bounds the pending map so a slow
    // daemon under sustained inbound load cannot grow it without limit.
    if ((this.pendingByClient.get(uuid) ?? 0) >= this.maxPendingPerClient) {
      throw new PendingCapExceededError(uuid);
    }

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
        this.removePending(id);
        reject(new ForwardTimeoutError(id));
      }, this.requestTimeoutMs);
      timer.unref();

      this.addPending(id, { uuid, resolve, reject, timer });
      this.sendServerMessage(client.ws, envelope);
    });
  }

  // ---------------------------------------------------------------------------
  // Pending-request bookkeeping — keeps `pending` and the per-client count in
  // lockstep so the outstanding-forward cap stays accurate across every exit
  // path (response, timeout, server close).
  // ---------------------------------------------------------------------------

  private addPending(id: string, req: PendingRequest): void {
    this.pending.set(id, req);
    this.pendingByClient.set(req.uuid, (this.pendingByClient.get(req.uuid) ?? 0) + 1);
  }

  private removePending(id: string): PendingRequest | undefined {
    const req = this.pending.get(id);
    if (req === undefined) return undefined;
    this.pending.delete(id);
    const count = this.pendingByClient.get(req.uuid) ?? 0;
    if (count <= 1) {
      this.pendingByClient.delete(req.uuid);
    } else {
      this.pendingByClient.set(req.uuid, count - 1);
    }
    return req;
  }

  close(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("Server closing"));
      }
      this.pending.clear();
      this.pendingByClient.clear();

      for (const client of this.clients.values()) {
        client.ws.terminate();
      }
      this.clients.clear();

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

  private handleConnection(ws: WebSocket, req: IncomingMessage): void {
    // A ws 'error' with no listener throws at the EventEmitter level and
    // takes the whole broker down — and rejected connections (4401/4402)
    // return before the lifecycle listeners below are attached, so a peer
    // that aborts after rejection would otherwise crash the process. Attach
    // the safety listener before anything can bail.
    ws.on("error", () => {
      ws.terminate();
    });

    // Identity comes from the TLS peer certificate; extract it before
    // accepting any frames. getPeerX509Certificate() can be undefined when
    // the socket presented no certificate.
    const socket = req.socket as TLSSocket;
    const peerCert =
      typeof socket.getPeerX509Certificate === "function"
        ? socket.getPeerX509Certificate()
        : undefined;
    if (peerCert === undefined) {
      this.sendError(ws, "client certificate required");
      ws.close(CLOSE_NO_CLIENT_CERT, "client certificate required");
      return;
    }
    const certPoint = extractP256PointFromCert(peerCert);
    if (certPoint === null) {
      this.sendError(ws, "client certificate key must be P-256");
      ws.close(CLOSE_CERT_NOT_P256, "client certificate key must be P-256");
      return;
    }
    const uuid = uuidFromP256Point(certPoint);

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
        // Only tear down the registry entry if it still belongs to THIS
        // socket — a reconnect for the same uuid may have replaced it, and
        // the old socket's close event must not delete the fresh entry.
        const current = this.clients.get(registeredUuid);
        if (current?.ws === ws) {
          this.emit("client:disconnected", registeredUuid);
          this.clients.delete(registeredUuid);
        }
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
          ws.close(CLOSE_BAD_HELLO, "expected hello message");
          return;
        }
        const hello = envelope.kind.value;
        const err = validateDecryptPubkey(hello);
        if (err !== null) {
          this.sendError(ws, err);
          ws.close(CLOSE_BAD_HELLO, err);
          return;
        }

        const decryptPubkeyBytes = Buffer.from(hello.decryptPubkey, "base64");

        // A reconnect for the same uuid replaces the previous socket. Detach
        // the old socket's registration first: its close event would
        // otherwise fire later, run its cleanup(), and delete THIS fresh
        // registration from the map.
        const previous = this.clients.get(uuid);
        if (previous !== undefined) {
          this.clients.delete(uuid);
          this.emit("client:disconnected", uuid);
          previous.ws.terminate();
        }

        this.clients.set(uuid, {
          ws,
          uuid,
          pubkey: certPoint,
          decryptPubkey: decryptPubkeyBytes,
        });
        registeredUuid = uuid;

        const welcomeEnvelope = create(ServerMessageSchema, {
          kind: {
            case: "welcome",
            value: {
              url: `${this.baseUrl}/u/${uuid}/hooks/`,
              protocol: PROTOCOL_VERSION,
              ...(this.brokerPubkey !== undefined ? { brokerPubkey: this.brokerPubkey } : {}),
            },
          },
        });
        this.sendServerMessage(ws, welcomeEnvelope);
        this.emit("client:connected", uuid);

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
      // HTTP status range guard (100–599). Proto3 int32 has no range constraint,
      // so a rogue daemon could emit out-of-range values. Drop rather than forward.
      if (response.status < 100 || response.status > 599) {
        return;
      }
      const req = this.removePending(response.id);
      if (req !== undefined) {
        clearTimeout(req.timer);
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

/**
 * Validates hello.decrypt_pubkey structurally and as an on-curve P-256
 * point. Required — every daemon advertises a split sign/decrypt identity.
 * Returns null on success, or an error string on failure.
 */
function validateDecryptPubkey(hello: Hello): string | null {
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
  return null;
}

// ---------------------------------------------------------------------------
// Re-export generated types for tests and external consumers.
export type { Request, Response } from "./pb/relay_pb.js";
