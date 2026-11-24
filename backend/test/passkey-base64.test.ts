import { describe, expect, test } from "bun:test";
import { decodeBase64 } from "../src/passkey.ts";

describe("passkey base64 validation", () => {
  test("decodes valid base64 and base64url, padded or not", () => {
    expect(decodeBase64("SGVsbG8=", "field").toString()).toBe("Hello");
    expect(decodeBase64("SGVsbG8", "field").toString()).toBe("Hello");
    expect(decodeBase64("a-b_", "field").length).toBe(3);
  });

  test("rejects bad characters instead of silently decoding them as empty", () => {
    expect(() => decodeBase64("@@@", "clientDataJSON")).toThrow("Invalid clientDataJSON");
    expect(() => decodeBase64("A", "signature")).toThrow("Invalid signature");
    expect(() => decodeBase64("", "signature")).toThrow("signature must be a non-empty base64 string");
  });
});
