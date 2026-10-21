import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { AudienceError, resolveAudience } from "../src/jwt.ts";
import { call, createSoftwareAuthenticator, createTestUser, login, loginOk, startApp, verifyWithJwks, type TestApp } from "./helpers.ts";

const both = { calendar: true, tracker: true };
const calendarOnly = { calendar: true, tracker: false };
const none = { calendar: false, tracker: false };

describe("resolveAudience", () => {
  test("without a request, lists every app the scopes allow", () => {
    expect(resolveAudience(undefined, both)).toEqual(["calendar", "tracker"]);
    expect(resolveAudience(null, calendarOnly)).toEqual(["calendar"]);
    expect(resolveAudience(undefined, none)).toEqual([]);
  });

  test("a named app narrows the audience to that app", () => {
    expect(resolveAudience("tracker", both)).toEqual(["tracker"]);
    expect(resolveAudience("calendar", both)).toEqual(["calendar"]);
  });

  test("refuses an app the scopes do not include, with 403", () => {
    expect.assertions(2);
    try {
      resolveAudience("tracker", calendarOnly);
    } catch (error) {
      expect(error).toBeInstanceOf(AudienceError);
      expect((error as AudienceError).statusCode).toBe(403);
    }
  });

  test.each([["mail"], [""], [7], [true], [["calendar"]], [{}]])("refuses the unknown or malformed audience %p with 400", (value) => {
    expect.assertions(2);
    try {
      resolveAudience(value, both);
    } catch (error) {
      expect(error).toBeInstanceOf(AudienceError);
      expect((error as AudienceError).statusCode).toBe(400);
    }
  });

  test("when required, a request that names no app is a 400 whatever the scopes", () => {
    for (const scopes of [both, calendarOnly, none]) {
      for (const requested of [undefined, null]) {
        expect(() => resolveAudience(requested, scopes, { required: true })).toThrow(AudienceError);
      }
    }
    try {
      resolveAudience(undefined, both, { required: true });
    } catch (error) {
      expect((error as AudienceError).statusCode).toBe(400);
      expect((error as AudienceError).message).toContain("calendar, tracker");
    }
  });

  test("when required, a named app still works and is still scope-checked", () => {
    expect(resolveAudience("calendar", both, { required: true })).toEqual(["calendar"]);
    expect(() => resolveAudience("tracker", calendarOnly, { required: true })).toThrow(AudienceError);
  });

  test("is not required by default", () => {
    expect(resolveAudience(undefined, both, {})).toEqual(["calendar", "tracker"]);
  });
});

describe("REQUIRE_AUDIENCE", () => {
  let app: TestApp;
  beforeAll(() => {
    app = startApp();
  });
  afterAll(() => app.stop());
  afterEach(() => {
    config.requireAudience = false;
  });

  test("is off by default, so old clients keep working", async () => {
    expect(config.requireAudience).toBe(false);
    const user = await createTestUser({ scopes: both });
    expect((await login(app, user)).status).toBe(200);
  });

  test("password login without an audience is refused, with one it works", async () => {
    config.requireAudience = true;
    const user = await createTestUser({ scopes: both });
    const refused = await login(app, user);
    expect(refused.status).toBe(400);
    expect((refused.body as any).error).toContain("audience is required");
    const ok = await login(app, user, { audience: "calendar" });
    expect(ok.status).toBe(200);
    expect(verifyWithJwks(ok.body.access_token).aud).toEqual(["calendar"]);
  });

  test("a refused request issues no tokens and does not count as a password failure", async () => {
    config.requireAudience = true;
    config.loginMaxFailures = 2;
    try {
      const user = await createTestUser({ scopes: both });
      for (let i = 0; i < 5; i++) expect((await login(app, user)).status).toBe(400);
      expect((await login(app, user, { audience: "tracker" })).status).toBe(200);
    } finally {
      config.loginMaxFailures = 5;
    }
  });

  test("passkey login without an audience is refused, with one it works", async () => {
    config.requireAudience = true;
    const user = await createTestUser({ scopes: both });
    const session = await loginOk(app, user, { audience: "calendar" });
    const authenticator = createSoftwareAuthenticator();
    const regOptions = await call(app, "POST", "/auth/passkey/register-options", { token: session.access_token });
    await call(app, "POST", "/auth/passkey/register-verify", { token: session.access_token, json: authenticator.registration(regOptions.body.challenge) });

    const first = await call(app, "POST", "/auth/passkey/login-options", { json: {} });
    const refused = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(first.body.challenge, { counter: 1 }) });
    expect(refused.status).toBe(400);

    const second = await call(app, "POST", "/auth/passkey/login-options", { json: {} });
    const ok = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(second.body.challenge, { counter: 1, audience: "tracker" }) });
    expect(ok.status).toBe(200);
    expect(verifyWithJwks(ok.body.access_token).aud).toEqual(["tracker"]);
  });

  test("refreshing a session opened before the flag still works", async () => {
    const user = await createTestUser({ scopes: both });
    const legacySession = await loginOk(app, user); // opened without an audience
    config.requireAudience = true;
    const refreshed = await call(app, "POST", "/auth/refresh", { json: { refresh_token: legacySession.refresh_token } });
    expect(refreshed.status).toBe(200);
    expect(verifyWithJwks(refreshed.body.access_token).aud).toEqual(["calendar", "tracker"]);
  });
});
