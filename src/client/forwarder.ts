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

export interface ForwardCtx {
  localPort: number;
  daemonUUID: string;
}

export async function dispatchRequest(
  req: RequestMessage,
  ctx: ForwardCtx,
): Promise<ResponseMessage> {
  // Allow-list paths to limit blast radius if relay is compromised.
  if (!req.path.startsWith("/hooks/") && req.path !== "/dicode.js") {
    return errorResponse(req.id, 403);
  }

  // Decode + cap body size.
  const body = req.body ? Buffer.from(req.body, "base64") : Buffer.alloc(0);
  if (body.length > MAX_BODY) return errorResponse(req.id, 413);

  // Build outgoing headers; drop inbound X-Relay-Base before re-stamping.
  const headers = new Headers();
  for (const [k, hv] of Object.entries(req.headers)) {
    if (k.toLowerCase() === "x-relay-base") continue;
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
