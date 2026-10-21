import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { getJwks } from "../src/keys.ts";
import { call, createTestUser, decode, login, loginOk, startApp, testSql, verifyWithJwks, type TestApp } from "./helpers.ts";

let app: TestApp;
beforeAll(() => {
  app = startApp();
});
afterAll(() => app.stop());

describe("POST /auth/login", () => {
  test("issues an ES256 access token that verifies against the published JWKS", async () => {
    const user = await createTestUser({ role: "admin", scopes: { calendar: true } });
    const tokens = await loginOk(app, user);

    const header = decode(tokens.access_token).header;
    expect(header.alg).toBe("ES256");
    expect(header.kid).toBe(getJwks().keys[0].kid);

    const claims = verifyWithJwks(tokens.access_token, { issuer: config.jwtIssuer });
    expect(claims.sub).toBe(user.id);
    expect(claims.username).toBe(user.username);
    expect(claims.role).toBe("admin");
    expect(claims.type).toBe("access");
    expect(claims.scopes).toEqual({ calendar: true, tracker: false });
    expect(claims.exp! - claims.iat!).toBe(config.accessTokenTtlSeconds);
    expect(tokens.expires_in).toBe(config.accessTokenTtlSeconds);
    expect(tokens.refresh_expires_in).toBe(config.refreshTokenTtlSeconds);
  });

  test("rejects a wrong password and an unknown user with the same message", async () => {
    const user = await createTestUser();
    const wrong = await login(app, { ...user, password: "nope" });
    const unknown = await login(app, { id: "x", username: "no-such-user-" + user.username, password: "nope" });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body as any);
  });

  test("requires username and password", async () => {
    const result = await call(app, "POST", "/auth/login", { json: { username: "someone" } });
    expect(result.status).toBe(400);
  });

  test("refuses a disabled account with 403", async () => {
    const user = await createTestUser({ active: false });
    const result = await login(app, user);
    expect(result.status).toBe(403);
    expect((result.body as any).error).toBe("Account disabled");
  });

  test("does not return a token in headers or a Location redirect", async () => {
    const user = await createTestUser();
    const result = await login(app, user);
    expect(result.headers.get("location")).toBeNull();
    expect(result.headers.get("set-cookie")).toBeNull();
  });
});

describe("audience", () => {
  test("lists every app the user may use when none is requested", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const claims = verifyWithJwks((await loginOk(app, user)).access_token);
    expect(claims.aud).toEqual(["calendar", "tracker"]);
  });

  test("narrows aud to the requested app", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const claims = verifyWithJwks((await loginOk(app, user, { audience: "tracker" })).access_token);
    expect(claims.aud).toEqual(["tracker"]);
  });

  test("refuses an app the user has no scope for (403)", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    const result = await login(app, user, { audience: "tracker" });
    expect(result.status).toBe(403);
  });

  test("refuses an unknown app (400)", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    expect((await login(app, user, { audience: "mail" })).status).toBe(400);
    expect((await login(app, user, { audience: 7 })).status).toBe(400);
  });

  test("a user with no app scopes gets a token no app accepts (no aud)", async () => {
    const user = await createTestUser();
    const claims = verifyWithJwks((await loginOk(app, user)).access_token);
    expect(claims.aud).toBeUndefined();
  });

  test("a token minted for the calendar does not name the tracker", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const claims = verifyWithJwks((await loginOk(app, user, { audience: "calendar" })).access_token);
    expect(claims.aud).not.toContain("tracker");
  });
});

describe("POST /auth/refresh", () => {
  const refresh = (refreshToken: string) => call(app, "POST", "/auth/refresh", { json: { refresh_token: refreshToken } });

  test("rotates the refresh token and issues a fresh access token", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    const first = await loginOk(app, user);
    const second = await refresh(first.refresh_token);
    expect(second.status).toBe(200);
    expect(second.body.refresh_token).not.toBe(first.refresh_token);
    expect(verifyWithJwks(second.body.access_token).sub).toBe(user.id);
  });

  test("keeps the app the session was opened for", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const first = await loginOk(app, user, { audience: "calendar" });
    const second = await refresh(first.refresh_token);
    expect(verifyWithJwks(second.body.access_token).aud).toEqual(["calendar"]);
  });

  test("a rotated token still works inside the grace period, not after it", async () => {
    const user = await createTestUser();
    const first = await loginOk(app, user);
    expect((await refresh(first.refresh_token)).status).toBe(200);
    // a parallel/retried refresh within the grace period
    expect((await refresh(first.refresh_token)).status).toBe(200);

    await testSql`UPDATE refresh_tokens SET rotated_at = now() - make_interval(secs => ${config.refreshReuseGraceSeconds + 5}) WHERE user_id = ${user.id}`;
    const late = await refresh(first.refresh_token);
    expect(late.status).toBe(401);
  });

  test("rejects an unknown or malformed refresh token", async () => {
    expect((await refresh("not-a-jwt")).status).toBe(401);
    expect((await call(app, "POST", "/auth/refresh", { json: {} })).status).toBe(400);
  });

  test("an access token is not accepted as a refresh token", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    expect((await refresh(tokens.access_token)).status).toBe(401);
  });

  test("losing the app's scope ends the session with 403 and revokes it", async () => {
    const user = await createTestUser({ scopes: { tracker: true } });
    const first = await loginOk(app, user, { audience: "tracker" });
    await testSql`UPDATE users SET scopes = '{"calendar": false, "tracker": false}'::jsonb WHERE id = ${user.id}`;
    const result = await refresh(first.refresh_token);
    expect(result.status).toBe(403);
    // revoked: no longer refreshable even after the scope returns
    await testSql`UPDATE users SET scopes = '{"calendar": false, "tracker": true}'::jsonb WHERE id = ${user.id}`;
    expect((await refresh(first.refresh_token)).status).toBe(401);
  });

  test("a disabled account gets 403 and all its tokens are revoked", async () => {
    const user = await createTestUser();
    const first = await loginOk(app, user);
    await testSql`UPDATE users SET active = false WHERE id = ${user.id}`;
    expect((await refresh(first.refresh_token)).status).toBe(403);
    await testSql`UPDATE users SET active = true WHERE id = ${user.id}`;
    expect((await refresh(first.refresh_token)).status).toBe(401);
  });
});

describe("POST /auth/logout", () => {
  test("revokes the refresh token outright, grace period notwithstanding", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    const out = await call(app, "POST", "/auth/logout", { json: { refresh_token: tokens.refresh_token } });
    expect(out.status).toBe(200);
    const after = await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } });
    expect(after.status).toBe(401);
  });

  test("rejects a missing or invalid token", async () => {
    expect((await call(app, "POST", "/auth/logout", { json: {} })).status).toBe(400);
    expect((await call(app, "POST", "/auth/logout", { json: { refresh_token: "junk" } })).status).toBe(401);
  });
});

describe("POST /auth/change-password", () => {
  test("changes the password and revokes every session", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    const changed = await call(app, "POST", "/auth/change-password", {
      token: tokens.access_token,
      json: { current_password: user.password, new_password: "brand-new-secret" },
    });
    expect(changed.status).toBe(200);

    expect((await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } })).status).toBe(401);
    expect((await login(app, user)).status).toBe(401);
    expect((await login(app, { ...user, password: "brand-new-secret" })).status).toBe(200);
  });

  test("requires the current password", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    const result = await call(app, "POST", "/auth/change-password", {
      token: tokens.access_token,
      json: { current_password: "wrong", new_password: "brand-new-secret" },
    });
    expect(result.status).toBe(401);
  });

  test("requires a bearer token and a new password that differs", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    expect((await call(app, "POST", "/auth/change-password", { json: { current_password: "a", new_password: "b" } })).status).toBe(401);
    expect(
      (await call(app, "POST", "/auth/change-password", { token: tokens.access_token, json: { current_password: user.password, new_password: user.password } })).status
    ).toBe(400);
    expect((await call(app, "POST", "/auth/change-password", { token: tokens.access_token, json: {} })).status).toBe(400);
  });
});

describe("discovery of keys and docs", () => {
  test("serves the JWKS with only the public key", async () => {
    const result = await call(app, "GET", "/.well-known/jwks.json");
    expect(result.status).toBe(200);
    const [key] = result.body.keys;
    expect(key).toMatchObject({ kty: "EC", crv: "P-256", use: "sig", alg: "ES256" });
    expect(key.d).toBeUndefined();
  });

  test("serves openapi.json and answers 404 for unknown routes", async () => {
    expect((await call(app, "GET", "/openapi.json")).status).toBe(200);
    expect((await call(app, "GET", "/auth/nope")).status).toBe(404);
  });
});
