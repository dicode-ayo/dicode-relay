import basicAuth from "express-basic-auth";
import type { RequestHandler } from "express";

/**
 * Basic-auth middleware for the status page.
 *
 * Behavior:
 * - If `password` is `undefined`, the status page is considered not configured
 *   and every request is answered with 404.
 * - Otherwise, we delegate to `express-basic-auth`, which performs a
 *   timing-safe credential comparison and emits a `WWW-Authenticate` challenge
 *   header on 401. The username is ignored — only the password is checked.
 */
export function statusAuth(password: string | undefined): RequestHandler {
  if (password === undefined) {
    return (_req, res, _next) => {
      res.status(404).json({ error: "status page not configured" });
    };
  }

  return basicAuth({
    authorizer: (_user: string, provided: string) => basicAuth.safeCompare(provided, password),
    challenge: true,
    realm: "dicode-relay status",
  });
}
