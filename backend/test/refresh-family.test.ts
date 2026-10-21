import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { call, createSoftwareAuthenticator, createTestUser, loginOk, startApp, testSql, type TestApp, type TestUser } from "./helpers.ts";

let app: TestApp;
beforeAll(() => {
  app = startApp();
});
afterAll(() => app.stop());

const refresh = (refreshToken: string) => call(app, "POST", "/auth/refresh", { json: { refresh_token: refreshToken } });

/** Pretends `seconds` have passed since every token of the user was rotated. */
const ageRotations = (user: TestUser, seconds: number) =>
  testSql`UPDATE refresh_tokens SET rotated_at = now() - make_interval(secs => ${seconds}) WHERE user_id = ${user.id} AND rotated_at IS NOT NULL`;

const outsideGrace = config.refreshReuseGraceSeconds + 5;

async function chain(user: TestUser, length: number) {
  const tokens = [await loginOk(app, user)];
  for (let i = 1; i < length; i++) {
    const next = await refresh(tokens[i - 1].refresh_token);
    expect(next.status).toBe(200);
    tokens.push(next.body);
  }
  return tokens;
}

async function auditRows(user: TestUser, event: string) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const rows = await testSql`SELECT success, detail FROM auth_events WHERE user_id = ${user.id} AND event = ${event}`;
    if (rows.length > 0) return rows;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return [];
}

describe("refresh token families (the legacy /auth/refresh)", () => {
  test("a login starts a family and every rotated token joins it", async () => {
    const user = await createTestUser();
    await chain(user, 3);
    const rows = await testSql`SELECT family_id FROM refresh_tokens WHERE user_id = ${user.id}`;
    expect(rows).toHaveLength(3);
    expect(rows.every((row: any) => row.family_id !== null)).toBe(true);
    expect(new Set(rows.map((row: any) => row.family_id)).size).toBe(1);
  });

  test("two logins are two families", async () => {
    const user = await createTestUser();
    await loginOk(app, user);
    await loginOk(app, user);
    const rows = await testSql`SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = ${user.id}`;
    expect(rows).toHaveLength(2);
  });

  test("replaying a rotated token after the grace period revokes the whole family, and says so", async () => {
    const user = await createTestUser();
    const [first, second, third] = await chain(user, 3);
    await ageRotations(user, outsideGrace);

    const replay = await refresh(first.refresh_token);
    expect(replay.status).toBe(401);

    // the legitimate holder of the newest token is cut off too: nothing in a replayed family can be trusted
    expect((await refresh(third.refresh_token)).status).toBe(401);
    expect((await refresh(second.refresh_token)).status).toBe(401);

    const [event] = await auditRows(user, "refresh_reuse");
    expect(event.success).toBe(false);
    expect(event.detail).toContain("outside the grace period");
    expect(event.detail).toContain("3 token(s)");
  });

  test("another login of the same user is a different family and survives", async () => {
    const user = await createTestUser();
    const [stolen] = await chain(user, 2);
    const unrelated = await loginOk(app, user);
    await ageRotations(user, outsideGrace);
    expect((await refresh(stolen.refresh_token)).status).toBe(401);
    expect((await refresh(unrelated.refresh_token)).status).toBe(200);
  });

  test("another user is never affected", async () => {
    const victim = await createTestUser();
    const bystander = await createTestUser();
    const [stolen] = await chain(victim, 2);
    const other = await loginOk(app, bystander);
    await ageRotations(victim, outsideGrace);
    await refresh(stolen.refresh_token);
    expect((await refresh(other.refresh_token)).status).toBe(200);
  });

  test("a retry inside the grace period is not treated as theft and revokes nothing", async () => {
    const user = await createTestUser();
    const [first, second] = await chain(user, 2);
    // a lost response, retried at once
    expect((await refresh(first.refresh_token)).status).toBe(200);
    expect((await refresh(second.refresh_token)).status).toBe(200);
    const rows = await testSql`SELECT 1 FROM auth_events WHERE user_id = ${user.id} AND event = 'refresh_reuse'`;
    expect(rows).toHaveLength(0);
    const [event] = await auditRows(user, "refresh");
    expect(event.detail).toContain("reused within grace period");
  });

  test("once a family is revoked the grace period cannot bring any of it back", async () => {
    const user = await createTestUser();
    const [first, second] = await chain(user, 2);
    await ageRotations(user, outsideGrace);
    await refresh(first.refresh_token); // outside grace: family revoked
    const rows = await testSql`SELECT revoked_at, rotated_at FROM refresh_tokens WHERE user_id = ${user.id}`;
    expect(rows.every((row: any) => row.revoked_at !== null && row.rotated_at === null)).toBe(true);
    expect((await refresh(second.refresh_token)).status).toBe(401);
    expect((await refresh(first.refresh_token)).status).toBe(401);
  });

  test("a token from before families existed counts as its own family", async () => {
    const user = await createTestUser();
    const legacy = await loginOk(app, user);
    await testSql`UPDATE refresh_tokens SET family_id = NULL WHERE user_id = ${user.id}`;

    const child = await refresh(legacy.refresh_token);
    expect(child.status).toBe(200);
    const rows = await testSql`SELECT id, family_id FROM refresh_tokens WHERE user_id = ${user.id} ORDER BY created_at`;
    expect(rows[0].family_id).toBeNull();
    expect(rows[1].family_id).toBe(rows[0].id); // the child joined its parent's id as the family

    await ageRotations(user, outsideGrace);
    expect((await refresh(legacy.refresh_token)).status).toBe(401);
    expect((await refresh(child.body.refresh_token)).status).toBe(401);
  });

  test("a family keeps its app", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const login = await loginOk(app, user, { audience: "calendar" });
    const next = await refresh(login.refresh_token);
    expect(next.status).toBe(200);
    const family = await testSql`SELECT count(DISTINCT family_id)::int AS n FROM refresh_tokens WHERE user_id = ${user.id}`;
    expect(family[0].n).toBe(1);
  });

  test("logout still revokes just the one token, not the family", async () => {
    const user = await createTestUser();
    const [, second] = await chain(user, 2);
    await call(app, "POST", "/auth/logout", { json: { refresh_token: second.refresh_token } });
    expect((await refresh(second.refresh_token)).status).toBe(401);
    const rows = await testSql`SELECT count(*)::int AS n FROM refresh_tokens WHERE user_id = ${user.id} AND revoked_at IS NOT NULL`;
    expect(rows[0].n).toBe(2); // the rotated parent and the logged-out child; no more tokens exist
  });
});

describe("the legacy login is marked deprecated", () => {
  const expectDeprecated = (response: { headers: Headers }) => {
    expect(response.headers.get("deprecation")).toBe("true");
    expect(response.headers.get("link")).toBe(`<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  };

  test("on /auth/login, whether it succeeds or fails", async () => {
    const user = await createTestUser();
    expectDeprecated(await call(app, "POST", "/auth/login", { json: { username: user.username, password: user.password } }));
    expectDeprecated(await call(app, "POST", "/auth/login", { json: { username: user.username, password: "wrong" } }));
    expectDeprecated(await call(app, "POST", "/auth/login", { json: {} }));
  });

  test("on the passkey login endpoints", async () => {
    const options = await call(app, "POST", "/auth/passkey/login-options", { json: {} });
    expectDeprecated(options);
    expectDeprecated(await call(app, "POST", "/auth/passkey/login-verify", { json: createSoftwareAuthenticator().assertion(options.body.challenge) }));
  });

  test("but not on the endpoints that stay: refresh, logout, change-password, the OP's own", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    for (const response of [
      await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } }),
      await call(app, "POST", "/auth/logout", { json: { refresh_token: tokens.refresh_token } }),
      await call(app, "GET", "/auth/me", { token: tokens.access_token }),
      await call(app, "GET", "/.well-known/openid-configuration"),
    ]) {
      expect(response.headers.get("deprecation")).toBeNull();
    }
  });

  test("and still honours audience while deprecated", async () => {
    const user = await createTestUser({ scopes: { calendar: true } });
    const response = await call(app, "POST", "/auth/login", { json: { username: user.username, password: user.password, audience: "tracker" } });
    expect(response.status).toBe(403);
    expectDeprecated(response);
  });
});
