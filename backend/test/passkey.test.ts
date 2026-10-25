import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { resetThrottleWindows } from "../src/throttle.ts";
import { call, createSoftwareAuthenticator, createTestUser, fromIp, loginOk, startApp, testSql, verifyWithJwks, type TestApp, type TestUser } from "./helpers.ts";

let app: TestApp;
const originalProxy = config.trustProxy;
beforeAll(() => {
  app = startApp();
});
afterAll(() => {
  app.stop();
  resetThrottleWindows();
});
beforeEach(() => {
  resetThrottleWindows();
});
afterEach(() => {
  config.trustProxy = originalProxy;
});

/** Registers a software passkey for `user` and returns it. */
async function registerPasskey(user: TestUser) {
  const session = await loginOk(app, user);
  const authenticator = createSoftwareAuthenticator();
  const options = await call(app, "POST", "/auth/passkey/register-options", { token: session.access_token });
  expect(options.status).toBe(200);
  const verified = await call(app, "POST", "/auth/passkey/register-verify", {
    token: session.access_token,
    json: authenticator.registration(options.body.challenge),
  });
  expect(verified.status).toBe(200);
  return { authenticator, session };
}

async function loginChallenge(username?: string) {
  const options = await call(app, "POST", "/auth/passkey/login-options", { json: username ? { username } : {} });
  expect(options.status).toBe(200);
  return options.body as { challenge: string; allowCredentials: { id: string }[] };
}

describe("passkey registration", () => {
  test("requires a session", async () => {
    expect((await call(app, "POST", "/auth/passkey/register-options")).status).toBe(401);
    expect((await call(app, "POST", "/auth/passkey/register-verify", { json: {} })).status).toBe(401);
  });

  test("registers a credential, lists it and deletes it", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    const { authenticator, session } = await registerPasskey(user);

    const listed = await call(app, "GET", "/auth/passkey/credentials", { token: session.access_token });
    expect(listed.body.map((entry: any) => entry.id)).toEqual([authenticator.credentialId]);
    expect(listed.body[0].deviceName).toBe("Test passkey");

    const deleted = await call(app, "DELETE", `/auth/passkey/credentials/${authenticator.credentialId}`, { token: session.access_token });
    expect(deleted.status).toBe(200);
    expect((await call(app, "GET", "/auth/passkey/credentials", { token: session.access_token })).body).toEqual([]);
  });

  test("rejects a response to a challenge that was never issued", async () => {
    const user = await createTestUser();
    const session = await loginOk(app, user);
    const authenticator = createSoftwareAuthenticator();
    await call(app, "POST", "/auth/passkey/register-options", { token: session.access_token });
    const result = await call(app, "POST", "/auth/passkey/register-verify", {
      token: session.access_token,
      json: authenticator.registration("not-the-challenge"),
    });
    expect(result.status).toBe(400);
  });

  test("cannot take over a credential id that belongs to another account", async () => {
    const owner = await createTestUser();
    const { authenticator } = await registerPasskey(owner);

    const thief = await createTestUser();
    const session = await loginOk(app, thief);
    const options = await call(app, "POST", "/auth/passkey/register-options", { token: session.access_token });
    const attempt = await call(app, "POST", "/auth/passkey/register-verify", {
      token: session.access_token,
      json: authenticator.registration(options.body.challenge),
    });
    expect(attempt.status).toBe(409);
    const rows = await testSql`SELECT user_id FROM passkey_credentials WHERE id = ${authenticator.credentialId}`;
    expect(rows[0].user_id).toBe(owner.id);
  });

  test("another user cannot delete someone else's passkey", async () => {
    const owner = await createTestUser();
    const { authenticator } = await registerPasskey(owner);
    const other = await createTestUser();
    const session = await loginOk(app, other);
    expect((await call(app, "DELETE", `/auth/passkey/credentials/${authenticator.credentialId}`, { token: session.access_token })).status).toBe(404);
  });
});

describe("passkey login", () => {
  test("signs in and returns tokens plus the user", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const { authenticator } = await registerPasskey(user);
    const { challenge, allowCredentials } = await loginChallenge(user.username);
    expect(allowCredentials.map((entry) => entry.id)).toContain(authenticator.credentialId);

    const result = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge) });
    expect(result.status).toBe(200);
    expect(result.body.user).toMatchObject({ id: user.id, username: user.username });
    const claims = verifyWithJwks(result.body.access_token);
    expect(claims.sub).toBe(user.id);
    expect(claims.aud).toEqual(["calendar", "tracker"]);
  });

  test("honours the requested audience", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    const result = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { audience: "tracker" }) });
    expect(result.status).toBe(200);
    expect(verifyWithJwks(result.body.access_token).aud).toEqual(["tracker"]);
  });

  test("refuses an app the user lacks, without consuming the counter", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    const refused = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { audience: "tracker", counter: 9 }) });
    expect(refused.status).toBe(403);
    const rows = await testSql`SELECT counter FROM passkey_credentials WHERE id = ${authenticator.credentialId}`;
    expect(Number(rows[0].counter)).toBe(0);
  });

  test("a challenge works exactly once", async () => {
    const user = await createTestUser();
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { counter: 1 }) })).status).toBe(200);
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { counter: 2 }) })).status).toBe(401);
  });

  test("rejects a bad signature", async () => {
    const user = await createTestUser();
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    const result = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { tamper: true }) });
    expect(result.status).toBe(401);
  });

  test("rejects an assertion without user presence", async () => {
    const user = await createTestUser();
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    const result = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { userPresent: false }) });
    expect(result.status).toBe(401);
  });

  test("rejects a replayed signature counter", async () => {
    const user = await createTestUser();
    const { authenticator } = await registerPasskey(user);
    const first = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(first.challenge, { counter: 5 }) })).status).toBe(200);
    const second = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(second.challenge, { counter: 5 }) })).status).toBe(401);
    const third = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(third.challenge, { counter: 6 }) })).status).toBe(200);
  });

  test("rejects an unknown credential", async () => {
    const stranger = createSoftwareAuthenticator();
    const { challenge } = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: stranger.assertion(challenge) })).status).toBe(401);
  });

  test("refuses a disabled account with 403", async () => {
    const user = await createTestUser();
    const { authenticator } = await registerPasskey(user);
    await testSql`UPDATE users SET active = false WHERE id = ${user.id}`;
    const { challenge } = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge) })).status).toBe(403);
  });

  test("a deleted passkey no longer signs in", async () => {
    const user = await createTestUser();
    const { authenticator, session } = await registerPasskey(user);
    await call(app, "DELETE", `/auth/passkey/credentials/${authenticator.credentialId}`, { token: session.access_token });
    const { challenge } = await loginChallenge();
    expect((await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge) })).status).toBe(401);
  });

  test("the refresh token it issues remembers the app", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const { authenticator } = await registerPasskey(user);
    const { challenge } = await loginChallenge();
    const result = await call(app, "POST", "/auth/passkey/login-verify", { json: authenticator.assertion(challenge, { audience: "calendar" }) });
    const refreshed = await call(app, "POST", "/auth/refresh", { json: { refresh_token: result.body.refresh_token } });
    expect(verifyWithJwks(refreshed.body.access_token).aud).toEqual(["calendar"]);
  });

  test("failed attempts are throttled per client address", async () => {
    config.trustProxy = true;
    const ip = fromIp(`198.51.100.${1 + Math.floor(Math.random() * 200)}`);
    const stranger = createSoftwareAuthenticator();
    const limit = config.loginMaxFailures * 5;
    for (let i = 0; i < limit; i++) {
      const { challenge } = await loginChallenge();
      const result = await call(app, "POST", "/auth/passkey/login-verify", { headers: ip, json: stranger.assertion(challenge) });
      expect(result.status).toBe(401);
    }
    const { challenge } = await loginChallenge();
    const blocked = await call(app, "POST", "/auth/passkey/login-verify", { headers: ip, json: stranger.assertion(challenge) });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).not.toBeNull();
  });
});
