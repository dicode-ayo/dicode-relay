/**
 * Golden vectors for the v4 signature preimages.
 *
 * The expected digests were computed by an independent implementation of the
 * layout (domain label, uint32-BE length-prefixed fields, fixed-width
 * timestamp). Pinning them byte-for-byte means a refactor cannot silently
 * change the wire contract — a mismatch here is a protocol break, not a bug
 * in the test.
 */

import { describe, it, expect } from "vitest";
import { buildSignedPayload, lengthPrefixed } from "../../src/shared/crypto.js";
import { buildDeliverySignaturePayload } from "../../src/shared/signing.js";

describe("v4 signature preimage golden vectors", () => {
  it("buildSignedPayload — OAuth auth request", () => {
    const digest = buildSignedPayload(
      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "dGVzdC1jaGFsbGVuZ2U", // base64url("test-challenge")
      "ab".repeat(32),
      "github",
      1_700_000_000,
    );
    expect(digest.toString("hex")).toBe(
      "3867bde5e22216683d285896c72a077283189a747e9b873d98a9b444552886d5",
    );
  });

  it("buildDeliverySignaturePayload — token delivery envelope", () => {
    const digest = buildDeliverySignaturePayload(
      "oauth_token_delivery",
      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "ZXBoZW1lcmFs",
      "Y2lwaGVydGV4dA==",
      "bm9uY2U=",
    );
    expect(digest.toString("hex")).toBe(
      "41ed4a19080b479b6e8d41e586ae9890d83812f27de3baf8e9b940d25b530c5f",
    );
  });

  it("length prefix is uint32-BE of the byte length", () => {
    const out = lengthPrefixed(Buffer.from("abc", "utf8"));
    expect(out.toString("hex")).toBe("00000003616263");
  });

  it("field-boundary shifts change the digest (injectivity)", () => {
    // Same concatenated bytes, different field split — must NOT collide.
    const a = buildDeliverySignaturePayload("ab", "c", "d", "e", "f");
    const b = buildDeliverySignaturePayload("a", "bc", "d", "e", "f");
    expect(a.equals(b)).toBe(false);
  });
});
