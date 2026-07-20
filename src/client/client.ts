import type { Identity } from "./identity.js";
import { Connection } from "./connection.js";

export interface RelayClientLogger {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
}

/** Status of a single broker connection within a (possibly multi-URL) client. */
export interface RelayEndpointStatus {
  /** The broker instance's mTLS URL this endpoint dials. */
  server_url: string;
  connected: boolean;
  hook_base_url?: string;
  broker_pubkey?: string;
  reconnect_attempts: number;
  last_error?: string;
  last_connected_at?: number; // unix seconds
}

export interface RelayStatus {
  /** True when at least one broker instance is connected. */
  connected: boolean;
  hook_base_url?: string;
  broker_pubkey?: string;
  /** Sum of reconnect attempts across all endpoints. */
  reconnect_attempts: number;
  last_error?: string;
  last_connected_at?: number; // unix seconds
  /**
   * Per-endpoint breakdown. Present only when the client spans more than one
   * broker URL; a single-URL client keeps the flat shape for back-compat.
   */
  endpoints?: RelayEndpointStatus[];
}

export interface RelayClientTls {
  /** PEM client certificate wrapping the identity's P-256 sign key
   *  (see Identity.mintClientCert). */
  certPem: string;
  /** PEM PKCS8 private key matching certPem. */
  keyPem: string;
  /**
   * PEM CA certificate(s) to verify the broker's server cert against.
   * Omit to use the platform trust store (WebPKI) — the right choice for the
   * hosted relay. Set for self-hosted brokers with self-signed certs.
   */
  ca?: string | string[];
}

export interface RelayClientOptions {
  /**
   * A single broker mTLS URL. Mutually exclusive with `serverURLs`; exactly
   * one of the two must be set. Kept for back-compat — equivalent to a
   * one-element `serverURLs`.
   */
  serverURL?: string;
  /**
   * One mTLS URL per broker instance. The client holds an independent control
   * connection to each concurrently, all sharing this identity/cert and
   * localPort, so every instance registers the same daemon uuid and can
   * forward locally. Mutually exclusive with `serverURL`.
   */
  serverURLs?: string[];
  localPort: number;
  identity: Identity;
  /** TLS client-certificate material. The connection is always wss://. */
  tls: RelayClientTls;
  /**
   * Called after each successful handshake with the broker's announced
   * delivery-signing pubkey (when present). Invoked once per connection, so a
   * multi-URL client calls it once per broker instance. The channel is
   * TLS-server-authenticated, so the consumer should persist the key
   * unconditionally (it verifies OAuth delivery envelopes out-of-band).
   * Awaited before that connection is reported as connected.
   */
  onBrokerPubkey?: (brokerPubkeyB64: string) => Promise<void>;
  log: RelayClientLogger;
  /** Called whenever aggregate connection state changes. Use for status reporting. */
  onStatus?: (s: RelayStatus) => void;
  /** Dial timeout in ms before a not-yet-open socket is abandoned. Default 15s. */
  dialTimeoutMs?: number;
  /** Timeout in ms for the app-level handshake (hello → welcome) after the
   *  socket opens. Guards against a broker that accepts the connection but
   *  never answers. Default 15s. */
  handshakeTimeoutMs?: number;
}

/**
 * Maintains one long-lived mTLS control connection per broker URL, reconnecting
 * each independently with exponential backoff. Every connection shares the same
 * identity (hence the same daemon uuid), so every broker instance holds this
 * daemon's socket and any instance can forward inbound `request` frames to
 * `http://localhost:<localPort>/<path>`. A request is always answered on the
 * connection it arrived on.
 */
export class RelayClient {
  private readonly urls: string[];

  constructor(private opts: RelayClientOptions) {
    this.urls = resolveServerURLs(opts);
  }

  /** Run forever (until `signal` is aborted), supervising one connection per URL. */
  async run(signal?: AbortSignal): Promise<void> {
    const endpoints = new Map<string, RelayEndpointStatus>();
    for (const url of this.urls) {
      endpoints.set(url, { server_url: url, connected: false, reconnect_attempts: 0 });
    }
    const multi = this.urls.length > 1;

    const conns = this.urls.map((url) => {
      const conn = new Connection({
        serverURL: url,
        localPort: this.opts.localPort,
        identity: this.opts.identity,
        tls: this.opts.tls,
        log: this.opts.log,
        ...(this.opts.onBrokerPubkey !== undefined
          ? { onBrokerPubkey: this.opts.onBrokerPubkey }
          : {}),
        ...(this.opts.dialTimeoutMs !== undefined
          ? { dialTimeoutMs: this.opts.dialTimeoutMs }
          : {}),
        ...(this.opts.handshakeTimeoutMs !== undefined
          ? { handshakeTimeoutMs: this.opts.handshakeTimeoutMs }
          : {}),
        onStatus: (s) => {
          endpoints.set(s.server_url, s);
          this.opts.onStatus?.(aggregateStatus(endpoints, multi));
        },
      });
      return conn.run(signal);
    });

    // Each connection retries until aborted and never rejects, so this resolves
    // only once every connection has observed the abort.
    await Promise.all(conns);
  }
}

/** Resolve the one-of `serverURL` / `serverURLs` config into a URL list. */
function resolveServerURLs(opts: RelayClientOptions): string[] {
  const hasSingle = opts.serverURL !== undefined;
  const hasList = opts.serverURLs !== undefined;
  if (hasSingle && hasList) {
    throw new Error("RelayClient: set either serverURL or serverURLs, not both");
  }
  if (!hasSingle && !hasList) {
    throw new Error("RelayClient: one of serverURL or serverURLs is required");
  }
  const urls = opts.serverURLs ?? (opts.serverURL !== undefined ? [opts.serverURL] : []);
  if (urls.length === 0) {
    throw new Error("RelayClient: serverURLs must not be empty");
  }
  const seen = new Set<string>();
  for (const u of urls) {
    if (typeof u !== "string" || u === "") {
      throw new Error("RelayClient: serverURLs entries must be non-empty strings");
    }
    // A duplicate URL would open two connections registering the same uuid on
    // one instance — the second silently replaces the first (server.ts
    // replace-on-reconnect), so it is a config error, not a valid fan-out.
    if (seen.has(u)) {
      throw new Error(`RelayClient: duplicate server URL ${u}`);
    }
    seen.add(u);
  }
  return urls;
}

/** Fold per-endpoint status into the aggregate the consumer's onStatus sees. */
function aggregateStatus(endpoints: Map<string, RelayEndpointStatus>, multi: boolean): RelayStatus {
  // Map insertion order mirrors the URL list, so endpoints stay in config order.
  const list = [...endpoints.values()];
  const up = list.filter((e) => e.connected);
  // Prefer a live endpoint so hook_base_url/broker_pubkey reflect a currently
  // forwarding instance; otherwise fall back to the most recently connected.
  const rep = up[0] ?? mostRecentlyConnected(list);

  const status: RelayStatus = {
    connected: up.length > 0,
    reconnect_attempts: list.reduce((n, e) => n + e.reconnect_attempts, 0),
  };
  if (rep?.hook_base_url !== undefined) status.hook_base_url = rep.hook_base_url;
  if (rep?.broker_pubkey !== undefined) status.broker_pubkey = rep.broker_pubkey;
  // A live representative has no pending error; surface one only while it is down.
  if (rep !== undefined && !rep.connected && rep.last_error !== undefined) {
    status.last_error = rep.last_error;
  }
  const lastConnectedAt = maxLastConnectedAt(list);
  if (lastConnectedAt !== undefined) status.last_connected_at = lastConnectedAt;
  if (multi) status.endpoints = list.map((e) => ({ ...e }));
  return status;
}

function mostRecentlyConnected(list: RelayEndpointStatus[]): RelayEndpointStatus | undefined {
  let best: RelayEndpointStatus | undefined;
  for (const e of list) {
    if (best === undefined) {
      best = e;
      continue;
    }
    if (
      e.last_connected_at !== undefined &&
      e.last_connected_at >= (best.last_connected_at ?? -1)
    ) {
      best = e;
    }
  }
  return best;
}

function maxLastConnectedAt(list: RelayEndpointStatus[]): number | undefined {
  let max: number | undefined;
  for (const e of list) {
    if (e.last_connected_at !== undefined && (max === undefined || e.last_connected_at > max)) {
      max = e.last_connected_at;
    }
  }
  return max;
}
