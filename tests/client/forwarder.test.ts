import { describe, expect, it } from "vitest";
import { create } from "@bufbuild/protobuf";
import { HeaderValuesSchema, RequestSchema } from "../../src/relay/pb/relay_pb.js";
import { dispatchRequest } from "../../src/client/forwarder.js";

function buildReq(
  over: Partial<{
    id: string;
    method: string;
    path: string;
    headers: Record<string, { values: string[] }>;
    body: string;
  }>,
) {
  const { headers: rawHeaders, ...rest } = over;
  return create(RequestSchema, {
    id: "00000000-0000-4000-8000-000000000000",
    method: "GET",
    path: "/hooks/x",
    body: "",
    ...rest,
    headers: Object.fromEntries(
      Object.entries(rawHeaders ?? {}).map(([k, v]) => [
        k,
        create(HeaderValuesSchema, { values: v.values }),
      ]),
    ),
  });
}

describe("dispatchRequest", () => {
  it("returns 403 for non-/hooks paths", async () => {
    const resp = await dispatchRequest(buildReq({ path: "/admin" }), {
      localPort: 0,
      daemonUUID: "abc",
    });
    expect(resp.status).toBe(403);
  });

  it("forwards body and returns response with X-Relay-Base", async () => {
    let receivedBase: string | null = null;
    let receivedBody: string | null = null;
    const http = await import("node:http");
    const srv = http.createServer((reqIn, resOut) => {
      const chunks: Buffer[] = [];
      reqIn.on("data", (c: Buffer) => chunks.push(c));
      reqIn.on("end", () => {
        receivedBase = reqIn.headers["x-relay-base"] as string;
        receivedBody = Buffer.concat(chunks).toString("utf8");
        resOut.statusCode = 200;
        resOut.setHeader("Content-Type", "text/plain");
        resOut.end(`echo:${receivedBody}`);
      });
    });
    await new Promise<void>((r) => {
      srv.listen(0, () => {
        r();
      });
    });
    const port = (srv.address() as { port: number }).port;

    const req = buildReq({
      method: "POST",
      path: "/hooks/test",
      headers: { "Content-Type": { values: ["text/plain"] } },
      body: Buffer.from("hi").toString("base64"),
    });
    const resp = await dispatchRequest(req, { localPort: port, daemonUUID: "abc" });

    srv.close();

    expect(resp.status).toBe(200);
    expect(receivedBase).toBe("/u/abc");
    expect(Buffer.from(resp.body, "base64").toString("utf8")).toBe("echo:hi");
  });

  it("filters hop-by-hop response headers", async () => {
    const http = await import("node:http");
    const srv = http.createServer((_reqIn, resOut) => {
      resOut.statusCode = 200;
      resOut.setHeader("Content-Type", "text/plain");
      resOut.setHeader("Connection", "keep-alive");
      resOut.setHeader("Set-Cookie", "session=abc");
      resOut.end("ok");
    });
    await new Promise<void>((r) => {
      srv.listen(0, () => {
        r();
      });
    });
    const port = (srv.address() as { port: number }).port;

    const resp = await dispatchRequest(buildReq({ path: "/hooks/x" }), {
      localPort: port,
      daemonUUID: "abc",
    });
    srv.close();

    const lowerKeys = Object.keys(resp.headers).map((k) => k.toLowerCase());
    expect(lowerKeys).not.toContain("connection");
    expect(lowerKeys).not.toContain("set-cookie");
    expect(lowerKeys).toContain("content-type");
  });

  it("returns 502 if local fetch fails (no server listening)", async () => {
    // Port 1 — connection refused.
    const resp = await dispatchRequest(buildReq({ path: "/hooks/x" }), {
      localPort: 1,
      daemonUUID: "abc",
    });
    expect(resp.status).toBe(502);
  });
});
