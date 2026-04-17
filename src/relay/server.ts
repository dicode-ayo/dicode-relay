/**
 * RelayServer — WebSocket server implementing the dicode relay protocol (PR #79).
 *
 * Responsibilities:
 *  - Challenge/response handshake with ECDSA P-256 signature verification
 *  - Connected-client registry (uuid → WebSocket + public key)
 *  - HTTP request forwarding to daemon over the established WebSocket
 *  - Ping/pong keepalive (30 s interval, 10 s timeout)
 */

import { createHash, createVerify } from "node:crypto";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import { type Server } from "node:http";
import { WebSocket, WebSocketServer } from "ws";
import { v4 as uuidv4 } from "uuid";
import { NonceStore } from "./nonces.js";
import type {
  ChallengeMessage,
  ClientMessage,
  ErrorMessage,
  HelloMessage,
  RequestMessage,
  ResponseMessage,
  ServerMessage,
  WelcomeMessage,
} from "./protocol.js";
import { HelloMessageSchema, ResponseMessageSchema } from "./protocol.js";

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

// ---------------------------------------------------------------------------
// Client registry entry
// ---------------------------------------------------------------------------

export interface ConnectedClient {
  ws: WebSocket;
  uuid: string;
  /** 65-byte uncompressed P-256 public key (0x04 || X || Y) */
  pubkey: Buffer;
}

// ---------------------------------------------------------------------------
// Pending forward request
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (response: ResponseMessage) => void;
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

  /**
   * Returns the port the WebSocket server is listening on.
   * Useful when port was set to 0 (random) in tests.
   */
  get port(): number {
    const addr = this.wss.address();
    if (typeof addr === "string" || addr === null) {
      throw new Error("Server address unavailable");
    }
    return addr.port;
  }

  /**
   * Retrieve a connected client by UUID.
   * Throws ClientNotConnectedError if not found.
   */
  getClient(uuid: string): ConnectedClient {
    const client = this.clients.get(uuid);
    if (client === undefined) {
      throw new ClientNotConnectedError(uuid);
    }
    return client;
  }

  /**
   * Returns true if the given UUID is currently connected.
   */
  hasClient(uuid: string): boolean {
    return this.clients.has(uuid);
  }

  /**
   * Forward an HTTP-style request to the daemon identified by `uuid`.
   * Returns a promise that resolves with the daemon's ResponseMessage.
   * Rejects with ForwardTimeoutError after 30 s or ClientNotConnectedError
   * if the daemon is not connected.
   */
  async forward(
    uuid: string,
    method: string,
    path: string,
    headers: Record<string, string[]>,
    body: Buffer,
  ): Promise<ResponseMessage> {
    const client = this.getClient(uuid);
    const id = uuidv4();

    const msg: RequestMessage = {
      type: "request",
      id,
      method,
      path,
      headers,
      body: body.toString("base64"),
    };

    return new Promise<ResponseMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new ForwardTimeoutError(id));
      }, this.requestTimeoutMs);
      timer.unref();

      this.pending.set(id, { resolve, reject, timer });
      this.sendMessage(client.ws, msg);
    });
  }

  /**
   * Close the WebSocket server and clean up all resources.
   */
  close(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      // Cancel all pending requests
      for (const [id, pending] of this.pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("Server closing"));
        this.pending.delete(id);
      }

      // Close all client connections
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
    // Send challenge immediately
    const nonce = randomBytes(32).toString("hex"); // 64 hex chars
    const challenge: ChallengeMessage = { type: "challenge", nonce };
    this.sendMessage(ws, challenge);

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

      if (registeredUuid === null) {
        // Expecting a hello message
        const result = HelloMessageSchema.safeParse(parsed);
        if (!result.success) {
          this.sendError(ws, "expected hello message");
          ws.close();
          return;
        }
        const hello = result.data;
        const err = this.verifyHello(hello, nonce);
        if (err !== null) {
          this.sendError(ws, err);
          ws.close();
          return;
        }

        const pubkeyBytes = Buffer.from(hello.pubkey, "base64");
        this.clients.set(hello.uuid, { ws, uuid: hello.uuid, pubkey: pubkeyBytes });
        registeredUuid = hello.uuid;

        const welcome: WelcomeMessage = {
          type: "welcome",
          url: `${this.baseUrl}/u/${hello.uuid}/hooks/`,
          ...(this.brokerPubkey !== undefined ? { broker_pubkey: this.brokerPubkey } : {}),
        };
        this.sendMessage(ws, welcome);
        this.emit("client:connected", hello.uuid);

        // Start keepalive
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

      // Expecting a response message
      const result = ResponseMessageSchema.safeParse(parsed);
      if (!result.success) {
        // Silently ignore unknown messages after registration
        return;
      }
      const response = result.data;
      const req = this.pending.get(response.id);
      if (req !== undefined) {
        clearTimeout(req.timer);
        this.pending.delete(response.id);
        req.resolve(response);
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
  private verifyHello(hello: HelloMessage, nonce: string): string | null {
    // Step 1: Decode pubkey — must be exactly 65 bytes starting with 0x04
    let pubkeyBytes: Buffer;
    try {
      pubkeyBytes = Buffer.from(hello.pubkey, "base64");
    } catch {
      return "invalid pubkey encoding";
    }
    if (pubkeyBytes.length !== 65 || pubkeyBytes[0] !== 0x04) {
      return "pubkey must be 65 bytes starting with 0x04";
    }

    // Step 2: Verify uuid == hex(sha256(pubkey))
    const expectedUuid = createHash("sha256").update(pubkeyBytes).digest("hex");
    if (expectedUuid !== hello.uuid) {
      return "uuid does not match sha256(pubkey)";
    }

    // Step 3: Verify timestamp within ±30 s
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - hello.timestamp) > this.timestampToleranceS) {
      return "timestamp out of range";
    }

    // Step 4: Verify nonce not seen in last 60 s
    if (this.nonces.check(nonce)) {
      return "nonce replayed";
    }

    // Step 5: Verify ECDSA signature over sha256(nonce_bytes || timestamp_be_uint64)
    // The Go client signs the raw sha256 digest with ecdsa.SignASN1, so we must
    // use createVerify("SHA256") on the raw (nonce || timestamp) bytes — Node's
    // createVerify("SHA256") hashes its input internally before verifying.
    const nonceBytes = Buffer.from(nonce, "hex");
    const tsBytes = Buffer.allocUnsafe(8);
    tsBytes.writeBigUInt64BE(BigInt(hello.timestamp));
    const message = Buffer.concat([nonceBytes, tsBytes]);

    try {
      const verify = createVerify("SHA256");
      verify.update(message);
      // Node.js accepts the raw 65-byte uncompressed key if we specify format correctly
      // We need to wrap it in a SubjectPublicKeyInfo DER structure for P-256
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

  private sendMessage(ws: WebSocket, msg: ServerMessage | ClientMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  }

  private sendError(ws: WebSocket, message: string): void {
    const err: ErrorMessage = { type: "error", message };
    this.sendMessage(ws, err);
  }
}

// ---------------------------------------------------------------------------
// DER encoding helper
// ---------------------------------------------------------------------------

/**
 * Wraps a raw 65-byte uncompressed P-256 public key into a DER-encoded
 * SubjectPublicKeyInfo structure so Node.js crypto can import it.
 *
 * SubjectPublicKeyInfo structure for EC P-256:
 *   SEQUENCE {
 *     SEQUENCE {
 *       OID 1.2.840.10045.2.1   (ecPublicKey)
 *       OID 1.2.840.10045.3.1.7 (prime256v1)
 *     }
 *     BIT STRING { 0x00, <65-byte pubkey> }
 *   }
 */
function uncompressedP256ToSpki(pubkey: Buffer): Buffer {
  // Fixed header for P-256 SPKI
  const header = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
  return Buffer.concat([header, pubkey]);
}
