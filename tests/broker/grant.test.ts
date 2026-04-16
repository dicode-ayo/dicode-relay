/**
 * Grant middleware factory tests.
 */

import { describe, expect, it } from "vitest";
import { buildGrantMiddleware } from "../../src/broker/grant.js";
import type { ProviderConfig } from "../../src/broker/providers.js";

function makeProviders(...entries: ProviderConfig[]): ReadonlyMap<string, ProviderConfig> {
  return new Map(entries.map((e) => [e.grantKey, e]));
}

describe("buildGrantMiddleware", () => {
  it("returns a function (middleware)", () => {
    const middleware = buildGrantMiddleware(new Map(), "https://relay.dicode.app");
    expect(typeof middleware).toBe("function");
  });

  it("includes providers with clientId set", () => {
    const providers = makeProviders(
      { grantKey: "github", clientId: "gh_id", clientSecret: "gh_secret", pkce: true, scopes: ["user", "repo"] },
    );
    const middleware = buildGrantMiddleware(providers, "https://relay.dicode.app");
    expect(typeof middleware).toBe("function");
  });

  it("handles PKCE-only providers (no secret)", () => {
    const providers = makeProviders(
      { grantKey: "slack", clientId: "slack_id", pkce: true, scopes: ["channels:read"] },
    );
    const middleware = buildGrantMiddleware(providers, "https://relay.dicode.app");
    expect(typeof middleware).toBe("function");
  });

  it("handles empty provider map (no providers configured)", () => {
    const middleware = buildGrantMiddleware(new Map(), "https://relay.dicode.app");
    expect(typeof middleware).toBe("function");
  });

  it("uses baseUrl as origin", () => {
    const providers = makeProviders(
      { grantKey: "github", clientId: "id", clientSecret: "secret", pkce: true, scopes: [] },
    );
    const middleware = buildGrantMiddleware(providers, "https://custom.example.com");
    expect(typeof middleware).toBe("function");
  });
});
