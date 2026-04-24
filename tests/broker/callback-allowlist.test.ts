/**
 * OAuth callback allowlist — dicode-relay#44.
 *
 * The callback URL is attacker-reachable: a malicious upstream OAuth
 * provider or an open-redirect exploited upstream could append extra
 * query parameters. Before #44 those extras were JSON-encoded, ECIES-
 * encrypted, and delivered to the daemon alongside the real token.
 *
 * The fix: allowlist the OAuth 2.0 RFC 6749 §5.1 response fields
 * plus `id_token` (OIDC) and `raw` (Grant convenience). Everything
 * else is dropped before encryption.
 */

import { describe, expect, it } from "vitest";
import { ALLOWED_TOKEN_FIELDS, filterCallbackTokenFields } from "../../src/broker/router.js";

describe("filterCallbackTokenFields", () => {
  it("passes through standard OAuth response fields", () => {
    const out = filterCallbackTokenFields({
      access_token: "abc",
      refresh_token: "def",
      token_type: "Bearer",
      expires_in: "3600",
      scope: "user repo",
      id_token: "oidc.jwt.here",
      raw: { provider_specific: 1 },
    });
    expect(out).toEqual({
      access_token: "abc",
      refresh_token: "def",
      token_type: "Bearer",
      expires_in: "3600",
      scope: "user repo",
      id_token: "oidc.jwt.here",
      raw: { provider_specific: 1 },
    });
  });

  it("drops injected attacker-controlled fields", () => {
    const out = filterCallbackTokenFields({
      access_token: "real",
      injected: "evil",
      "x-admin": "true",
      __proto__: "pollution",
    });
    expect(out).toEqual({ access_token: "real" });
    expect("injected" in out).toBe(false);
    expect("x-admin" in out).toBe(false);
  });

  it("drops the state field (it is session metadata, never a token)", () => {
    const out = filterCallbackTokenFields({
      state: "session-uuid",
      access_token: "real",
    });
    expect(out).toEqual({ access_token: "real" });
  });

  it("handles empty input", () => {
    expect(filterCallbackTokenFields({})).toEqual({});
  });

  it("ALLOWED_TOKEN_FIELDS matches RFC 6749 §5.1 + id_token + raw", () => {
    expect(ALLOWED_TOKEN_FIELDS).toEqual([
      "access_token",
      "refresh_token",
      "token_type",
      "expires_in",
      "scope",
      "id_token",
      "raw",
    ]);
  });
});
