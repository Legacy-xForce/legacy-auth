import { describe, expect, test } from "bun:test";
import jwt from "jsonwebtoken";
import { config } from "../src/config.ts";
import { getPrivateKey } from "../src/keys.ts";
import { signAccessToken, verifyAccessToken } from "../src/jwt.ts";
import { call, createTestUser, startApp } from "./helpers.ts";

const SUB = "11111111-1111-4111-8111-111111111111";

/** Signs a token with the service's own key, as the OpenID Provider does. */
function signAsOp(payload: Record<string, unknown>, options: jwt.SignOptions = {}) {
  return jwt.sign(payload, getPrivateKey(), {
    algorithm: "ES256",
    issuer: config.jwtIssuer,
    keyid: "test-key",
    expiresIn: 600,
    ...options,
  });
}

describe("verifyAccessToken — only access tokens from this issuer", () => {
  test("accepts a legacy access token", () => {
    const token = signAccessToken({
      sub: SUB, username: "alice", role: "user", scopes: { calendar: true, tracker: false }, audience: ["calendar"],
    });
    expect(verifyAccessToken(token).sub).toBe(SUB);
  });

  test("accepts an access token issued by the OpenID Provider", () => {
    // The OP signs with the same key and marks its access tokens with type: "access".
    const token = signAsOp({ sub: SUB, type: "access", aud: "calendar", scopes: { calendar: true, tracker: false } });
    expect(verifyAccessToken(token).type).toBe("access");
  });

  test("rejects an ID token, which shares the key but is not an access token", () => {
    const token = signAsOp({ sub: SUB, aud: "calendar-spa", nonce: "n" });
    expect(() => verifyAccessToken(token)).toThrow();
  });

  test("rejects a correctly typed token from another issuer", () => {
    const token = jwt.sign({ sub: SUB, type: "access" }, getPrivateKey(), {
      algorithm: "ES256", issuer: "https://evil.example", expiresIn: 600,
    });
    expect(() => verifyAccessToken(token)).toThrow();
  });
});

describe("the legacy bearer endpoints", () => {
  test("an ID token is not accepted as a bearer token", async () => {
    const user = await createTestUser();
    const app = startApp();
    try {
      const idToken = signAsOp({ sub: user.id, aud: "calendar-spa", nonce: "n" });
      const response = await call(app, "GET", "/auth/me", { token: idToken });
      expect(response.status).toBe(401);
    } finally {
      app.stop();
    }
  });
});
