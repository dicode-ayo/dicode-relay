import { timingSafeEqual } from "node:crypto";

import type { RequestHandler } from "express";

export function statusAuth(password: string | undefined): RequestHandler {
  return (req, res, next) => {
    if (password === undefined) {
      res.status(404).json({ error: "status page not configured" });
      return;
    }

    const authHeader = req.headers.authorization;
    if (authHeader === undefined) {
      res.setHeader("WWW-Authenticate", 'Basic realm="dicode-relay status"');
      res.status(401).json({ error: "authentication required" });
      return;
    }

    const match = /^Basic\s+(.+)$/i.exec(authHeader);
    const credentials = match?.[1];
    if (credentials === undefined) {
      res.status(401).json({ error: "invalid auth format" });
      return;
    }

    const decoded = Buffer.from(credentials, "base64").toString("utf8");
    const colonIndex = decoded.indexOf(":");
    const providedPassword = colonIndex === -1 ? decoded : decoded.substring(colonIndex + 1);

    const provided = Buffer.from(providedPassword, "utf8");
    const expected = Buffer.from(password, "utf8");
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      res.status(401).json({ error: "invalid credentials" });
      return;
    }

    next();
  };
}
