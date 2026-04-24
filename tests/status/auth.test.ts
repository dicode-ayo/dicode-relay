import { describe, expect, it, afterEach } from "vitest";
import express from "express";
import { createServer, type Server } from "node:http";
import { statusAuth } from "../../src/status/auth.js";

function startApp(password: string | undefined): Promise<{ port: number; server: Server }> {
  const app = express();
  app.use(statusAuth(password));
  app.get("/test", (_req, res) => {
    res.json({ ok: true });
  });
  const server = createServer(app);
  return new Promise((resolve) => {
    server.listen(0, () => {
      const addr = server.address();
      if (typeof addr === "object" && addr !== null) {
        resolve({ port: addr.port, server });
      }
    });
  });
}

function basicAuthHeader(password: string): string {
  return "Basic " + Buffer.from(":" + password).toString("base64");
}

describe("statusAuth middleware", () => {
  let server: Server | null = null;

  afterEach(() => {
    if (server !== null) {
      server.close();
      server = null;
    }
  });

  it("returns 404 when STATUS_PASSWORD is undefined", async () => {
    const { port, server: s } = await startApp(undefined);
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`);
    expect(res.status).toBe(404);
  });

  it("returns 401 with WWW-Authenticate when no auth header sent", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe('Basic realm="dicode-relay status"');
  });

  it("returns 401 for wrong password", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("wrongpassword") },
    });
    expect(res.status).toBe(401);
  });

  it("returns 200 for correct password", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("secret123") },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it("rejects wrong password of different length without throwing", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("x") },
    });
    expect(res.status).toBe(401);
  });

  it("rejects wrong password of equal length", async () => {
    const { port, server: s } = await startApp("secret123");
    server = s;
    const res = await fetch(`http://localhost:${port.toString()}/test`, {
      headers: { authorization: basicAuthHeader("xxxxxxxxx") },
    });
    expect(res.status).toBe(401);
  });
});
