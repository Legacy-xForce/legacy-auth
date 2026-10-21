import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { call, createTestUser, loginOk, startApp, testSql, type TestApp, type TestUser } from "./helpers.ts";
import { Browser, ISSUER_ORIGIN, basicAuth, pkce, refreshRequest, registerClient, signInAndRedeem, tokenRequest, useStubFrontend } from "./oidc-helpers.ts";

let app: TestApp;
let restoreFrontend: () => void;
let adminToken: string;
const original = { proxy: config.trustProxy };

beforeAll(async () => {
  app = startApp();
  restoreFrontend = useStubFrontend();
  adminToken = (await loginOk(app, await createTestUser({ role: "admin" }))).access_token;
});
afterAll(() => {
  app.stop();
  restoreFrontend();
});
afterEach(() => {
  config.trustProxy = original.proxy;
});

const both = { calendar: true, tracker: true };

type Row = { event: string; success: boolean; user_id: string | null; username: string | null; ip: string | null; user_agent: string | null; detail: string | null };

/** The user's events of one kind. Audit rows are written without holding up requests, so wait for `count` of them. */
async function events(user: Pick<TestUser, "id">, event: string, count = 1): Promise<Row[]> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const rows = await testSql<Row[]>`SELECT event, success, user_id, username, ip, user_agent, detail FROM auth_events WHERE user_id = ${user.id} AND event = ${event} ORDER BY id`;
    if (rows.length >= count) return rows;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return testSql<Row[]>`SELECT event, success, user_id, username, ip, user_agent, detail FROM auth_events WHERE user_id = ${user.id} AND event = ${event} ORDER BY id`;
}

describe("sign-in", () => {
  test("oidc.login records a success, with the user, the method, the address and the user agent", async () => {
    config.trustProxy = true;
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge });
    const result = await browser.interactionCall(start.interaction!.uid, "login", { username: user.username, password: user.password }, { "x-forwarded-for": "198.51.100.42", "user-agent": "Mozilla/5.0 (audit test)" });
    expect(result.status).toBe(200);

    const [row] = await events(user, "oidc.login");
    expect(row).toMatchObject({ success: true, username: user.username, detail: "pwd", ip: "198.51.100.42", user_agent: "Mozilla/5.0 (audit test)" });
  });

  test("oidc.login records a failure with the reason, and links it to the user when there is one", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge });
    await browser.interactionCall(start.interaction!.uid, "login", { username: user.username, password: "wrong" });
    const [row] = await events(user, "oidc.login");
    expect(row.success).toBe(false);
    expect(row.detail).toBe("Invalid credentials");
    expect(row.username).toBe(user.username);
  });

  test("a name that belongs to nobody is recorded too, so account guessing can be searched for", async () => {
    const ghost = `ghost-${Math.random().toString(16).slice(2, 10)}`;
    const client = await registerClient();
    const browser = new Browser(app);
    const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    await browser.interactionCall(uid, "login", { username: ghost, password: "guess" });
    let rows: Row[] = [];
    for (let attempt = 0; attempt < 100 && rows.length === 0; attempt++) {
      rows = await testSql<Row[]>`SELECT event, success, user_id, username, ip, user_agent, detail FROM auth_events WHERE event = 'oidc.login' AND username = ${ghost}`;
      if (rows.length === 0) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ success: false, user_id: null, detail: "Invalid credentials" });
    const found = await call(app, "GET", `/admin/audit-events?username=${ghost}`, { token: adminToken });
    expect(found.body.total).toBe(1);
  });

  test("a throttled attempt is recorded as such", async () => {
    const limit = config.loginMaxFailures;
    config.loginMaxFailures = 2;
    try {
      const user = await createTestUser({ scopes: both });
      const client = await registerClient();
      const browser = new Browser(app);
      const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
      for (let i = 0; i < 3; i++) await browser.interactionCall(uid, "login", { username: user.username, password: "wrong" });
      // the throttled attempt is refused before the account is looked up, so it is found by name
      let rows: Row[] = [];
      for (let attempt = 0; attempt < 100 && rows.length < 3; attempt++) {
        rows = await testSql<Row[]>`SELECT event, success, user_id, username, ip, user_agent, detail FROM auth_events WHERE event = 'oidc.login' AND username = ${user.username} ORDER BY id`;
        if (rows.length < 3) await new Promise((resolve) => setTimeout(resolve, 20));
      }
      expect(rows.map((row) => row.detail)).toEqual(["Invalid credentials", "Invalid credentials", "throttled"]);
    } finally {
      config.loginMaxFailures = limit;
    }
  });

  test("a disabled account's attempt is recorded against that account", async () => {
    const user = await createTestUser({ scopes: both, active: false });
    const client = await registerClient();
    const browser = new Browser(app);
    const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    await browser.interactionCall(uid, "login", { username: user.username, password: user.password });
    const [row] = await events(user, "oidc.login");
    expect(row).toMatchObject({ success: false });
    expect(row.detail).toContain("Account disabled");
  });
});

describe("authorization codes and tokens", () => {
  test("oidc.code.issued, then oidc.token.issued for the code and for each refresh", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    await refreshRequest(app, client, tokens.body.refresh_token);

    const [code] = await events(user, "oidc.code.issued");
    expect(code).toMatchObject({ success: true, detail: client.id, username: user.username });

    const issued = await events(user, "oidc.token.issued", 2);
    expect(issued.map((row) => row.detail)).toEqual([`${client.id} authorization_code`, `${client.id} refresh_token`]);
  });

  test("a refused consent is recorded with the reason", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: false } });
    const client = await registerClient();
    await new Browser(app).flow(client, user, { resource: "urn:legacy:tracker", scope: "openid tracker.read", challenge: pkce().challenge });
    const [row] = await events(user, "oidc.consent");
    expect(row.success).toBe(false);
    expect(row.detail).toContain(client.id);
    expect(row.detail).toContain("no access to tracker");
  });

  test("a malformed authorization request is recorded as an error", async () => {
    const client = await registerClient();
    const before = Date.now();
    await new Browser(app).request(`${ISSUER_ORIGIN}/authorize?${new URLSearchParams({ client_id: client.id, redirect_uri: client.redirect, response_type: "code", scope: "openid", nonce: "n", state: "s" })}`);
    let row: Row | undefined;
    for (let attempt = 0; attempt < 100 && !row; attempt++) {
      row = (await testSql<Row[]>`SELECT event, success, user_id, username, ip, user_agent, detail FROM auth_events WHERE event = 'oidc.authorize' AND detail LIKE ${`${client.id}:%`}`)[0];
      if (!row) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(Date.now() - before).toBeLessThan(5000);
    expect(row?.success).toBe(false);
    expect(row?.detail).toContain("invalid_request");
  });

  test("a rotated refresh token presented again is oidc.refresh.reuse", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    await refreshRequest(app, client, tokens.body.refresh_token);
    await refreshRequest(app, client, tokens.body.refresh_token);
    const [row] = await events(user, "oidc.refresh.reuse");
    expect(row.success).toBe(false);
    expect(row.detail).toContain(client.id);
    expect(row.detail).toContain("revoked");
  });

  test("an ordinary refresh is not reported as reuse", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    const first = await refreshRequest(app, client, tokens.body.refresh_token);
    await refreshRequest(app, client, first.body.refresh_token);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(await testSql`SELECT 1 FROM auth_events WHERE event = 'oidc.refresh.reuse' AND user_id = ${user.id}`).toHaveLength(0);
  });
});

describe("the audit log is usable and safe", () => {
  test("an admin can find the OP's events by name and user", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    await signInAndRedeem(app, new Browser(app), client, user);
    await events(user, "oidc.token.issued");
    const result = await call(app, "GET", `/admin/audit-events?event=oidc.login&userId=${user.id}`, { token: adminToken });
    expect(result.status).toBe(200);
    expect(result.body.items).toHaveLength(1);
    expect(result.body.items[0]).toMatchObject({ event: "oidc.login", success: true, username: user.username });
  });

  test("no event holds a password, a secret, a code, a token or a cookie", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { tokens, redirect } = await signInAndRedeem(app, browser, client, user);
    const wrong = await new Browser(app).authorize(client, { challenge: pkce().challenge });
    await new Browser(app).interactionCall(wrong.interaction!.uid, "login", { username: user.username, password: "a-wrong-password-9876" });
    await tokenRequest(app, { grant_type: "authorization_code", code: "x" }, basicAuth(client.id, "wrong-client-secret-1234"));
    await refreshRequest(app, client, tokens.body.refresh_token);
    await new Promise((resolve) => setTimeout(resolve, 200));

    const dump = JSON.stringify(await testSql`SELECT * FROM auth_events`);
    for (const secret of [user.password, "a-wrong-password-9876", "wrong-client-secret-1234", client.secret!, redirect.searchParams.get("code")!, tokens.body.access_token, tokens.body.refresh_token, tokens.body.id_token, browser.cookie("__Host-legacy_session")!]) {
      expect(dump).not.toContain(secret);
    }
  });

  test("every event has a timestamp, an outcome and the source", async () => {
    const user = await createTestUser({ scopes: both });
    await signInAndRedeem(app, new Browser(app), await registerClient(), user);
    await events(user, "oidc.token.issued");
    const rows = await testSql`SELECT created_at, success, event FROM auth_events WHERE user_id = ${user.id} AND event LIKE 'oidc.%'`;
    expect(rows.length).toBeGreaterThanOrEqual(3);
    for (const row of rows) {
      expect(row.created_at).toBeTruthy();
      expect(typeof row.success).toBe("boolean");
    }
  });

  test("a failure to write an audit row never breaks the request", async () => {
    const user = await createTestUser({ scopes: both });
    await testSql`ALTER TABLE auth_events RENAME TO auth_events_away`;
    const originalError = console.error;
    console.error = () => {};
    try {
      const { tokens } = await signInAndRedeem(app, new Browser(app), await registerClient(), user);
      expect(tokens.status).toBe(200);
    } finally {
      // the last events are written in the background; let them fail before the table is put back
      await new Promise((resolve) => setTimeout(resolve, 400));
      console.error = originalError;
      await testSql`ALTER TABLE auth_events_away RENAME TO auth_events`;
    }
  });

  test("OP events are subject to the same retention as the rest", async () => {
    const user = await createTestUser({ scopes: both });
    await signInAndRedeem(app, new Browser(app), await registerClient(), user);
    // the token event is written in the background; wait for the last one so none lands after the backdating below
    await events(user, "oidc.token.issued");
    await testSql`UPDATE auth_events SET created_at = now() - interval '400 days' WHERE user_id = ${user.id} AND event LIKE 'oidc.%'`;
    const { pruneAuditNow } = await import("../src/audit-retention.ts");
    await pruneAuditNow(180);
    expect(await testSql`SELECT 1 FROM auth_events WHERE user_id = ${user.id} AND event LIKE 'oidc.%'`).toHaveLength(0);
  });
});
