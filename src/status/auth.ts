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
    if (match === null || match[1] === undefined) {
      res.status(401).json({ error: "invalid auth format" });
      return;
    }

    const decoded = Buffer.from(match[1], "base64").toString("utf8");
    const colonIndex = decoded.indexOf(":");
    const providedPassword = colonIndex === -1 ? decoded : decoded.substring(colonIndex + 1);

    if (providedPassword !== password) {
      res.status(401).json({ error: "invalid credentials" });
      return;
    }

    next();
  };
}
