import WebSocket from "ws";
import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";
import { ClientMessageSchema, ServerMessageSchema } from "../relay/pb/relay_pb.js";
import type { Identity } from "./identity.js";
import { runHandshake, type SocketLike, type TofuResult } from "./handshake.js";
import { dispatchRequest } from "./forwarder.js";
import { newBackoff } from "./backoff.js";

const STABLE_MS = 10_000;
const DIAL_TIMEOUT_MS = 15_000;

export interface RelayClientLogger {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface RelayStatus {
  connected: boolean;
  hook_base_url?: string;
  broker_pubkey?: string;
  reconnect_attempts: number;
  last_error?: string;
  last_connected_at?: number; // unix seconds
}

export interface RelayClientOptions {
  serverURL: string;
  localPort: number;
  identity: Identity;
  /**
   * Trust-on-first-use callback. Receives the broker's announced pubkey;
   * the consumer compares against its persisted record and returns:
   *   - "new"      — the consumer MUST persist the key before returning,
   *                  otherwise TOFU is defeated (every connect would be
   *                  treated as first-seen, accepting any key).
   *   - "match"    — the announced key matches what the consumer pinned;
   *                  the handshake continues normally.
   *   - "mismatch" — the announced key differs from the pinned record;
   *                  RelayClient rejects the handshake.
   */
  tofuCheckAndPin: (brokerPubkeyB64: string) => Promise<TofuResult>;
  log: RelayClientLogger;
  /** Called whenever connection state changes. Use for status reporting. */
  onStatus?: (s: RelayStatus) => void;
  /** Dial timeout in ms before a not-yet-open socket is abandoned. Default 15s. */
  dialTimeoutMs?: number;
}

/**
 * Maintains a long-lived WebSocket connection to the relay server. Reconnects
 * with exponential backoff on disconnect. Forwards inbound `request` frames to
 * `http://localhost:<localPort>/<path>` via fetch, sends `response` back.
 */
export class RelayClient {
  constructor(private opts: RelayClientOptions) {}

  /**
   * Run forever (until `signal` is aborted). Each iteration is one connection
   * attempt: dial, handshake, serve until close, then back off.
   */
  async run(signal?: AbortSignal): Promise<void> {
    const bo = newBackoff();
    const status: RelayStatus = { connected: false, reconnect_attempts: 0 };

    while (signal?.aborted !== true) {
      const start = Date.now();
      try {
        await this.runOnce(status, signal);
        if (Date.now() - start >= STABLE_MS) bo.reset();
        // Clean disconnect — flip status before backoff sleep so health reporters see "down".
        status.connected = false;
        this.opts.onStatus?.(status);
      } catch (err) {
        status.connected = false;
        status.last_error = String(err);
        status.reconnect_attempts++;
        this.opts.onStatus?.(status);
        this.opts.log.warn("relay disconnected", { err: String(err) });
      }
      const wait = bo.next();
      // Allow signal to interrupt the backoff sleep.
      let backoffHandle: ReturnType<typeof setTimeout> | undefined;
      const timer = new Promise<void>((r) => {
        backoffHandle = setTimeout(r, wait);
      });
      const aborted = new Promise<void>((r) => {
        // An abort that landed *during* runOnce (e.g. mid-dial) leaves the
        // signal already aborted here; addEventListener never fires
        // retroactively, so without this the client would sleep the full
        // backoff before noticing and exit slowly on shutdown.
        if (signal?.aborted === true) {
          r();
          return;
        }
        signal?.addEventListener(
          "abort",
          () => {
            r();
          },
          { once: true },
        );
      });
      await Promise.race([timer, aborted]);
      if (backoffHandle !== undefined) clearTimeout(backoffHandle);
    }
  }

  private async runOnce(status: RelayStatus, signal?: AbortSignal): Promise<void> {
    // The dial timeout is enforced manually below rather than via ws's
    // { handshakeTimeout } option: under Deno's node:http polyfill ws leaves its
    // internal handshake timer armed after "open", so it later fires
    // abortHandshake() on an already-nulled request (TypeError: reading
    // 'setHeader' of null) and tears a healthy connection down ~DIAL_TIMEOUT_MS
    // after connecting, causing a permanent reconnect flap.
    const ws = new WebSocket(this.opts.serverURL);

    // Register the message adapter BEFORE awaiting "open". The relay server sends
    // a challenge frame immediately upon connection. If we registered the listener
    // after the "open" promise resolves, the challenge could arrive (and be dropped
    // by the EventEmitter) during the microtask gap between open firing and our
    // .then() continuation — causing recv() in runHandshake to hang forever.
    const { sock, detach } = adaptWs(ws);

    await new Promise<void>((resolve, reject) => {
      // terminate() on a still-CONNECTING socket emits an 'error' on the next
      // tick; cleanup() has already removed our 'error' listener, so without a
      // catch-all that becomes an unhandled 'error' event (uncaughtException /
      // process crash). Swallow it before aborting the dial.
      const terminateQuietly = (): void => {
        ws.once("error", () => {});
        ws.terminate();
      };
      const dialTimer = setTimeout((): void => {
        cleanup();
        terminateQuietly();
        reject(new Error("dial timeout"));
      }, this.opts.dialTimeoutMs ?? DIAL_TIMEOUT_MS);
      const onAbort = (): void => {
        cleanup();
        terminateQuietly();
        reject(new Error("aborted"));
      };
      const onOpen = (): void => {
        cleanup();
        resolve();
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };
      const onClose = (): void => {
        cleanup();
        reject(new Error("closed before open"));
      };
      const cleanup = (): void => {
        clearTimeout(dialTimer);
        signal?.removeEventListener("abort", onAbort);
        ws.removeListener("open", onOpen);
        ws.removeListener("error", onError);
        ws.removeListener("close", onClose);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      ws.once("open", onOpen);
      ws.once("error", onError);
      ws.once("close", onClose);
    });

    try {
      const hr = await runHandshake(sock, this.opts.identity, this.opts.tofuCheckAndPin);
      // Detach the handshake message listener and collect any frames that
      // arrived in the microtask gap between the welcome frame and detach().
      // The broker may pipeline welcome + a request back-to-back; without
      // replay those frames would be silently lost.
      const leftover = detach();
      if (leftover.length > 0) {
        this.opts.log.warn("relay: replayed buffered frames at handshake→serve", {
          count: leftover.length,
        });
      }
      // Replay buffered frames BEFORE serve() registers its listener so that
      // each frame still goes through handleFrame exactly once.
      for (const raw of leftover) {
        void this.handleFrame(ws, raw);
      }

      Object.assign(status, {
        connected: true,
        hook_base_url: hr.hookBaseURL,
        broker_pubkey: hr.brokerPubkey,
        last_error: undefined,
        last_connected_at: Math.floor(Date.now() / 1000),
      });
      this.opts.onStatus?.(status);
      this.opts.log.info("relay connected", { url: hr.hookBaseURL });

      await this.serve(ws, signal);
    } finally {
      try {
        ws.terminate();
      } catch {
        /* already closed */
      }
    }
  }

  private serve(ws: WebSocket, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const onAbort = (): void => {
        ws.terminate();
      };
      const onClose = (): void => {
        cleanup();
        resolve();
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };
      const onMessage = (data: Buffer | string): void => {
        void this.handleFrame(ws, data);
      };
      const cleanup = (): void => {
        signal?.removeEventListener("abort", onAbort);
        ws.removeListener("close", onClose);
        ws.removeListener("error", onError);
        ws.removeListener("message", onMessage);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      ws.on("close", onClose);
      ws.on("error", onError);
      ws.on("message", onMessage);
    });
  }

  private async handleFrame(ws: WebSocket, data: Buffer | string): Promise<void> {
    try {
      const raw = typeof data === "string" ? data : data.toString("utf8");
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw) as unknown;
      } catch {
        this.opts.log.warn("relay: malformed JSON from server");
        return;
      }
      let env;
      try {
        env = fromJson(ServerMessageSchema, parsed as JsonValue, { ignoreUnknownFields: true });
      } catch {
        this.opts.log.warn("relay: malformed envelope");
        return;
      }
      if (env.kind.case !== "request") return;

      const resp = await dispatchRequest(env.kind.value, {
        localPort: this.opts.localPort,
        daemonUUID: this.opts.identity.uuid,
      });
      const out = create(ClientMessageSchema, { kind: { case: "response", value: resp } });
      ws.send(JSON.stringify(toJson(ClientMessageSchema, out, { useProtoFieldName: true })));
    } catch (err) {
      this.opts.log.warn("relay: handleFrame error", { err: String(err) });
    }
  }
}

/** Adapt the `ws` WebSocket to the SocketLike interface used by runHandshake. */
function adaptWs(ws: WebSocket): { sock: SocketLike; detach: () => string[] } {
  const inbox: string[] = [];
  const waiters: ((s: string) => void)[] = [];

  const onMessage = (data: Buffer | string): void => {
    const raw = typeof data === "string" ? data : data.toString("utf8");
    const next = waiters.shift();
    if (next) next(raw);
    else inbox.push(raw);
  };

  ws.on("message", onMessage);

  return {
    sock: {
      send: (s) => {
        ws.send(s);
      },
      recv: () =>
        new Promise<string>((r) => {
          const queued = inbox.shift();
          if (queued !== undefined) r(queued);
          else waiters.push(r);
        }),
    },
    detach: (): string[] => {
      // Remove the handshake listener so it no longer buffers incoming frames.
      // Return any frames that arrived after the final handshake message — they
      // are pre-serve request frames that must be replayed into handleFrame so
      // they are not silently lost during the handshake→serve transition gap.
      ws.removeListener("message", onMessage);
      return inbox.splice(0);
    },
  };
}
