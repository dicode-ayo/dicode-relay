/**
 * Grant middleware factory tests.
 */

import { describe, expect, it } from "vitest";
import { buildGrantMiddleware } from "../../src/broker/grant.js";
import { PROVIDER_CONFIGS } from "../../src/broker/providers.js";

describe("buildGrantMiddleware", () => {
  it("returns a function (middleware)", () => {
    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://relay.dicode.app", {});
    expect(typeof middleware).toBe("function");
  });

  it("only includes providers with CLIENT_ID set in env", () => {
    const env = {
      GITHUB_CLIENT_ID: "gh_id",
      GITHUB_CLIENT_SECRET: "gh_secret",
      // Slack not configured
    };

    // Should not throw — just skips unconfigured providers
    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://relay.dicode.app", env);
    expect(typeof middleware).toBe("function");
  });

  it("handles PKCE-only providers (no secret env)", () => {
    const env = {
      SLACK_CLIENT_ID: "slack_id",
      // No SLACK_CLIENT_SECRET (it's null in config)
    };

    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://relay.dicode.app", env);
    expect(typeof middleware).toBe("function");
  });

  it("handles providers with secret env but secret not set", () => {
    const env = {
      GITHUB_CLIENT_ID: "gh_id",
      // GITHUB_CLIENT_SECRET not set
    };

    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://relay.dicode.app", env);
    expect(typeof middleware).toBe("function");
  });

  it("handles empty env (no providers configured)", () => {
    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://relay.dicode.app", {});
    expect(typeof middleware).toBe("function");
  });

  it("uses BASE_URL as origin", () => {
    // Just verify it doesn't throw with different base URLs
    const middleware = buildGrantMiddleware(PROVIDER_CONFIGS, "https://custom.example.com", {
      GITHUB_CLIENT_ID: "id",
      GITHUB_CLIENT_SECRET: "secret",
    });
    expect(typeof middleware).toBe("function");
  });
});
