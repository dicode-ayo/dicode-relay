import { posix } from "node:path";
import { create } from "@bufbuild/protobuf";
import { HeaderValuesSchema, ResponseSchema } from "../relay/pb/relay_pb.js";
import type { RequestMessage, ResponseMessage } from "../shared/protocol.js";

const MAX_BODY = 5 * 1024 * 1024;

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "set-cookie", // sensitive — never forward to inbound caller
]);

// Headers we refuse to forward from the relay to the local daemon. A
// compromised relay could otherwise inject forged credentials targeting
// daemon-side handlers. Match case-insensitively.
const STRIP_INBOUND = new Set(["authorization", "cookie", "x-api-key"]);

export interface ForwardCtx {
  localPort: number;
  daemonUUID: string;
}

export async function dispatchRequest(
  req: RequestMessage,
  ctx: ForwardCtx,
): Promise<ResponseMessage> {
  // req.path is an origin-form request-target: split the raw query off before
  // the allow-list checks (only the path component is validated) and re-attach
  // it verbatim on fetch so percent-encoded values survive without a
  // decode/re-encode round-trip.
  const queryIdx = req.path.indexOf("?");
  const barePath = queryIdx === -1 ? req.path : req.path.slice(0, queryIdx);

  // Normalise the path before allow-list checks to prevent path-traversal
  // bypasses via ".." segments or percent-encoded variants.
  let decoded: string;
  try {
    decoded = decodeURIComponent(barePath);
  } catch {
    return errorResponse(req.id, 400);
  }
  const normalised = posix.normalize(decoded);
  // If normalisation changed anything (e.g. ".." collapsed, "//" folded, or
  // the raw path contained percent-encoded sequences) — reject.
  if (normalised !== decoded || normalised !== barePath) {
    return errorResponse(req.id, 403);
  }
  if (!normalised.startsWith("/hooks/") && normalised !== "/dicode.js") {
    return errorResponse(req.id, 403);
  }

  // Decode + cap body size.
  const body = req.body ? Buffer.from(req.body, "base64") : Buffer.alloc(0);
  if (body.length > MAX_BODY) return errorResponse(req.id, 413);

  // Build outgoing headers; drop inbound X-Relay-Base before re-stamping.
  const headers = new Headers();
  for (const [k, hv] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (lk === "x-relay-base") continue; // re-stamped below
    if (STRIP_INBOUND.has(lk)) continue; // never forward credential headers
    for (const v of hv.values) headers.append(k, v);
  }
  headers.set("X-Relay-Base", `/u/${ctx.daemonUUID}`);

  let resp: Response;
  try {
    resp = await fetch(`http://localhost:${String(ctx.localPort)}${req.path}`, {
      method: req.method,
      headers,
      ...(body.length > 0 ? { body } : {}),
      signal: AbortSignal.timeout(25_000),
    });
  } catch {
    return errorResponse(req.id, 502);
  }

  // Read at most MAX_BODY bytes of response body.
  const reader = resp.body?.getReader();
  let buf = Buffer.alloc(0);
  if (reader) {
    let done = false;
    while (!done) {
      const result = await reader.read();
      done = result.done;
      if (!done) {
        const chunk = Buffer.from(result.value);
        if (buf.length + chunk.length > MAX_BODY) {
          buf = Buffer.concat([buf, chunk.subarray(0, MAX_BODY - buf.length)]);
          await reader.cancel();
          done = true;
        } else {
          buf = Buffer.concat([buf, chunk]);
        }
      }
    }
  }

  const respHeaders: Record<string, ReturnType<typeof create<typeof HeaderValuesSchema>>> = {};
  for (const [k, v] of resp.headers) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    const existing = respHeaders[k];
    if (existing) existing.values.push(v);
    else respHeaders[k] = create(HeaderValuesSchema, { values: [v] });
  }

  return create(ResponseSchema, {
    id: req.id,
    status: resp.status,
    headers: respHeaders,
    body: buf.toString("base64"),
  });
}

function errorResponse(id: string, status: number): ResponseMessage {
  return create(ResponseSchema, { id, status, headers: {}, body: "" });
}
