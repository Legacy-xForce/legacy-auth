import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "crypto";
import { config } from "../src/config.ts";
import { processDueRetries } from "../src/oidc/backchannel.ts";
import { oidc } from "../src/oidc/index.ts";
import { sessionTtlSeconds } from "../src/oidc/provider.ts";
import { call, createTestUser, decode, loginOk, startApp, testSql, verifyWithJwks, type TestApp, type TestUser } from "./helpers.ts";
import {
  Browser,
  ISSUER,
  ISSUER_ORIGIN,
  pkce,
  refreshRequest,
  registerClient,
  signInAndRedeem,
  startBackchannelStub,
  useStubFrontend,
  type BackchannelStub,
  type TestClient,
} from "./oidc-helpers.ts";

let app: TestApp;
let restoreFrontend: () => void;
const original = {
  delays: config.oidcBackchannelRetryDelaysMs,
  internal: config.oidcAllowInternalBackchannel,
};

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(() => {
  app.stop();
  restoreFrontend();
});
afterEach(() => {
  config.oidcBackchannelRetryDelaysMs = original.delays;
  config.oidcAllowInternalBackchannel = original.internal;
});

const both = { calendar: true, tracker: true };
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Polls until `check` returns something truthy, so tests do not depend on fixed sleeps. */
async function eventually<T>(check: () => Promise<T | false | null | undefined> | T | false | null | undefined, ms = 5000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) throw new Error("condition not met in time");
    await sleep(25);
  }
}

type Signed = Awaited<ReturnType<typeof signInAndRedeem>>;

/** An app with a back-channel endpoint, signed in as `user` in `browser`. */
async function signedInApp(browser: Browser, user: TestUser, stubOptions: Parameters<typeof startBackchannelStub>[0] = {}) {
  const stub = await startBackchannelStub(stubOptions);
  const client = await registerClient({ backchannel_logout_uri: stub.url });
  const signed = await signInAndRedeem(app, browser, client, user);
  return { stub, client, signed };
}

/** What RP-initiated logout does in a browser: the page, then the form it submits. */
async function rpLogout(browser: Browser, client: TestClient, signed: Signed, options: { hint?: boolean; postLogout?: string; state?: string } = {}) {
  const query = new URLSearchParams({ client_id: client.id });
  if (options.hint !== false) query.set("id_token_hint", signed.tokens.body.id_token);
  query.set("post_logout_redirect_uri", options.postLogout ?? client.logoutRedirect!);
  query.set("state", options.state ?? "bye");
  const page = await browser.request(`${ISSUER_ORIGIN}/logout?${query}`);
  const html = await page.clone().text();
  const action = html.match(/<form[^>]*id="op\.logoutForm"[^>]*action="([^"]+)"/)?.[1] ?? html.match(/<form[^>]*action="([^"]+)"[^>]*id="op\.logoutForm"/)?.[1];
  const fields: Record<string, string> = {};
  for (const [, name, value] of html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)"/g)) fields[name] = value;
  return {
    page,
    html,
    action,
    fields,
    confirm: async (overrides: Record<string, string> = {}) =>
      browser.request(action!, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ ...fields, ...overrides }),
      }),
  };
}

describe("the logout page", () => {
  test("submits itself when the app asked (it proved who it is with an id_token_hint)", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    const logout = await rpLogout(browser, client, signed);
    expect(logout.page.status).toBe(200);
    expect(logout.html).toContain(`document.getElementById("op.logoutForm").submit()`);
    expect(logout.fields.logout).toBe("yes");
    expect(logout.fields.xsrf).toBeString();
  });

  test("its only script is allowed by hash, and nothing else may run", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    const logout = await rpLogout(browser, client, signed);
    const script = logout.html.match(/<script>([\s\S]*?)<\/script>/)![1];
    const hash = createHash("sha256").update(script).digest("base64");
    const csp = logout.page.headers.get("content-security-policy")!;
    expect(csp).toContain(`'sha256-${hash}'`);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    const scriptSrc = csp.split(";").map((directive) => directive.trim()).find((directive) => directive.startsWith("script-src"))!;
    expect(scriptSrc).toBe(`script-src 'sha256-${hash}'`); // the hash and nothing else: no unsafe-inline, no unsafe-eval, no hosts
    expect(logout.html.match(/<script/g)).toHaveLength(1);
  });

  test("asks first when nobody vouched for the request, and never loads anything from outside", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    const logout = await rpLogout(browser, client, signed, { hint: false });
    expect(logout.page.status).toBe(200);
    expect(logout.html).not.toContain("<script");
    expect(logout.html).toContain("Sign out of all apps");
    expect(logout.html).not.toMatch(/https?:\/\/(?!auth\.test\.local)/);
  });

  test("without a session there is nothing to confirm", async () => {
    const response = await new Browser(app).request(`${ISSUER_ORIGIN}/logout`);
    expect(response.status).toBeLessThan(500);
  });

  test("the post-logout page is a plain statement, not an app", async () => {
    const response = await new Browser(app).request(`${ISSUER_ORIGIN}/logout/success`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("signed out");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  });
});

describe("RP-initiated logout", () => {
  test("ends the session, clears the cookie and goes back to the registered address with the state", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    const logout = await rpLogout(browser, client, signed, { state: "see-you" });
    const done = await logout.confirm();
    expect(done.status).toBe(303);
    const location = new URL(done.headers.get("location")!);
    expect(`${location.origin}${location.pathname}`).toBe(new URL(client.logoutRedirect!).origin + new URL(client.logoutRedirect!).pathname);
    expect(location.searchParams.get("state")).toBe("see-you");
    expect(browser.cookie("__Host-legacy_session")).toBeUndefined();
    const rows = await testSql`SELECT revoked_at FROM oidc_sessions WHERE user_id = ${user.id}`;
    expect(rows.every((row: any) => row.revoked_at !== null)).toBe(true);
  });

  test("does not act on a form without the right anti-forgery token", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    const logout = await rpLogout(browser, client, signed);
    const forged = await logout.confirm({ xsrf: "not-the-token" });
    expect(forged.status).toBeGreaterThanOrEqual(400);
    // still signed in
    const probe = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(probe.redirect?.searchParams.get("code")).toBeString();
  });

  test("logging out of one app logs out of all of them, and ends their refresh tokens", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const calendar = await signedInApp(browser, user);
    const tracker = await signedInApp(browser, user);

    await (await rpLogout(browser, calendar.client, calendar.signed)).confirm();

    expect((await refreshRequest(app, calendar.client, calendar.signed.tokens.body.refresh_token)).status).toBe(400);
    expect((await refreshRequest(app, tracker.client, tracker.signed.tokens.body.refresh_token)).status).toBe(400);
    for (const { client } of [calendar, tracker]) {
      const probe = await new Browser(app).authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid" });
      expect(probe.redirect?.searchParams.get("error")).toBe("login_required");
    }
    const again = await browser.authorize(tracker.client, { challenge: pkce().challenge });
    expect(again.interaction).toBeDefined();
  });

  test("is recorded in the audit log", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client, signed } = await signedInApp(browser, user);
    await (await rpLogout(browser, client, signed)).confirm();
    const row = await eventually(async () => (await testSql`SELECT detail, username FROM auth_events WHERE event = 'oidc.logout' AND user_id = ${user.id}`)[0]);
    expect(row.username).toBe(user.username);
    expect(row.detail).toBe(client.id);
  });

  test("the legacy /auth/logout is separate: it does not end the OP session", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { client } = await signedInApp(browser, user);
    const legacy = await loginOk(app, user);
    await call(app, "POST", "/auth/logout", { json: { refresh_token: legacy.refresh_token } });
    const probe = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(probe.redirect?.searchParams.get("code")).toBeString();
  });
});

describe("back-channel logout", () => {
  test("reaches every app the browser was signed in to, in under five seconds", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const calendar = await signedInApp(browser, user);
    const tracker = await signedInApp(browser, user);
    try {
      const logout = await rpLogout(browser, calendar.client, calendar.signed);
      const started = Date.now();
      await logout.confirm();
      await eventually(() => calendar.stub.hits.length > 0 && tracker.stub.hits.length > 0);
      expect(Date.now() - started).toBeLessThan(5000);
      expect(calendar.stub.hits).toHaveLength(1);
      expect(tracker.stub.hits).toHaveLength(1);
    } finally {
      calendar.stub.stop();
      tracker.stub.stop();
    }
  });

  test("sends a signed logout_token bound to that app's session", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const calendar = await signedInApp(browser, user);
    try {
      await (await rpLogout(browser, calendar.client, calendar.signed)).confirm();
      await eventually(() => calendar.stub.hits.length > 0);
      const token = new URLSearchParams(calendar.stub.hits[0].body).get("logout_token")!;
      expect(decode(token).header).toMatchObject({ alg: "ES256", typ: "logout+jwt" });
      const claims = verifyWithJwks(token, { issuer: ISSUER, audience: calendar.client.id }) as any;
      expect(claims.sub).toBe(user.id);
      expect(claims.events).toEqual({ "http://schemas.openid.net/event/backchannel-logout": {} });
      expect(claims.sid).toBe((decode(calendar.signed.tokens.body.access_token).payload as any).sid);
      expect(claims.jti).toBeString();
      expect(claims.iat).toBeNumber();
      expect(claims.exp).toBeGreaterThan(claims.iat);
      expect(claims.nonce).toBeUndefined();
    } finally {
      calendar.stub.stop();
    }
  });

  test("a logout_token for one app is not valid for another", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const calendar = await signedInApp(browser, user);
    const tracker = await signedInApp(browser, user);
    try {
      await (await rpLogout(browser, calendar.client, calendar.signed)).confirm();
      await eventually(() => calendar.stub.hits.length > 0 && tracker.stub.hits.length > 0);
      const forCalendar = new URLSearchParams(calendar.stub.hits[0].body).get("logout_token")!;
      expect(() => verifyWithJwks(forCalendar, { audience: tracker.client.id })).toThrow(/audience invalid/);
      const sids = [calendar, tracker].map((entry) => (decode(new URLSearchParams(entry.stub.hits[0].body).get("logout_token")!).payload as any).sid);
      expect(sids[0]).not.toBe(sids[1]);
    } finally {
      calendar.stub.stop();
      tracker.stub.stop();
    }
  });

  test("a client with no back-channel endpoint is simply not called, and nothing fails", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const client = await registerClient();
    const signed = await signInAndRedeem(app, browser, client, user);
    const done = await (await rpLogout(browser, client, signed)).confirm();
    expect(done.status).toBe(303);
    expect((await testSql`SELECT count(*)::int AS n FROM oidc_backchannel_retries WHERE account_id = ${user.id}`)[0].n).toBe(0);
  });

  test("a delivery that fails is retried with backoff until it gets through", async () => {
    config.oidcBackchannelRetryDelaysMs = [40, 40, 40];
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const app1 = await signedInApp(browser, user, { failFirst: 2 });
    try {
      const done = await (await rpLogout(browser, app1.client, app1.signed)).confirm();
      expect(done.status).toBe(303); // a slow or failing app never blocks the user's logout
      expect(app1.stub.hits).toHaveLength(1);
      await eventually(async () => (await testSql`SELECT 1 FROM oidc_backchannel_retries WHERE account_id = ${user.id}`).length === 1);

      for (let round = 0; round < 6 && app1.stub.hits.length < 3; round++) {
        await sleep(60);
        await processDueRetries(oidc.provider);
      }
      expect(app1.stub.hits).toHaveLength(3);
      expect((await testSql`SELECT count(*)::int AS n FROM oidc_backchannel_retries WHERE account_id = ${user.id}`)[0].n).toBe(0);

      const events = await testSql`SELECT success, detail FROM auth_events WHERE event = 'oidc.backchannel' AND user_id = ${user.id} ORDER BY id`;
      expect(events.filter((event: any) => event.success === false)).toHaveLength(2);
      expect(events.at(-1)).toMatchObject({ success: true });
      expect(events.at(-1).detail).toContain("delivered on attempt 3");
    } finally {
      app1.stub.stop();
    }
  });

  test("gives up after the last delay, and says so in the audit log", async () => {
    config.oidcBackchannelRetryDelaysMs = [20, 20];
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const dead = await signedInApp(browser, user, { failFirst: 100 });
    try {
      await (await rpLogout(browser, dead.client, dead.signed)).confirm();
      for (let round = 0; round < 8; round++) {
        await sleep(40);
        await processDueRetries(oidc.provider);
      }
      expect(dead.stub.hits).toHaveLength(3); // the first try plus one per delay
      expect((await testSql`SELECT count(*)::int AS n FROM oidc_backchannel_retries WHERE account_id = ${user.id}`)[0].n).toBe(0);
      const last = (await testSql`SELECT success, detail FROM auth_events WHERE event = 'oidc.backchannel' AND user_id = ${user.id} ORDER BY id DESC LIMIT 1`)[0];
      expect(last.success).toBe(false);
      expect(last.detail).toContain("gave up after 3 attempts");
    } finally {
      dead.stub.stop();
    }
  });

  test("two workers never send the same retry twice", async () => {
    config.oidcBackchannelRetryDelaysMs = [10, 10];
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const flaky = await signedInApp(browser, user, { failFirst: 1 });
    try {
      await (await rpLogout(browser, flaky.client, flaky.signed)).confirm();
      await sleep(30);
      await Promise.all([processDueRetries(oidc.provider), processDueRetries(oidc.provider), processDueRetries(oidc.provider)]);
      expect(flaky.stub.hits).toHaveLength(2); // the failed first try, and exactly one retry
    } finally {
      flaky.stub.stop();
    }
  });

  test("never calls an internal address in production settings, even one registered earlier", async () => {
    config.oidcBackchannelRetryDelaysMs = [1000];
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const target = await signedInApp(browser, user);
    try {
      config.oidcAllowInternalBackchannel = false; // as in production
      await (await rpLogout(browser, target.client, target.signed)).confirm();
      await sleep(200);
      expect(target.stub.hits).toHaveLength(0);
      const event = await eventually(async () => (await testSql`SELECT detail FROM auth_events WHERE event = 'oidc.backchannel' AND user_id = ${user.id}`)[0]);
      expect(event.detail).toMatch(/refusing to call .* (is an internal address|local or private)/);
    } finally {
      target.stub.stop();
    }
  });
});

describe("ending every session of an account", () => {
  async function adminToken() {
    return (await loginOk(app, await createTestUser({ role: "admin" }))).access_token;
  }

  async function twoApps(user: TestUser) {
    const browser = new Browser(app);
    const first = await signedInApp(browser, user);
    const second = await signedInApp(browser, user);
    return { browser, apps: [first, second] };
  }

  const stopAll = (apps: { stub: BackchannelStub }[]) => apps.forEach((entry) => entry.stub.stop());

  async function expectEnded(user: TestUser, browser: Browser, apps: Awaited<ReturnType<typeof twoApps>>["apps"]) {
    await eventually(() => apps.every((entry) => entry.stub.hits.length > 0));
    for (const entry of apps) {
      expect((await refreshRequest(app, entry.client, entry.signed.tokens.body.refresh_token)).status).toBe(400);
    }
    const rows = await testSql`SELECT revoked_at FROM oidc_sessions WHERE user_id = ${user.id}`;
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((row: any) => row.revoked_at !== null)).toBe(true);
    const leftovers = await testSql`SELECT 1 FROM oidc_payloads WHERE payload->>'accountId' = ${user.id} AND model IN ('Grant','RefreshToken','AccessToken','AuthorizationCode')`;
    expect(leftovers).toHaveLength(0);
    void browser;
  }

  test("an admin disabling the account tells every app and ends its tokens", async () => {
    const user = await createTestUser({ scopes: both });
    const { browser, apps } = await twoApps(user);
    try {
      await call(app, "PATCH", `/admin/users/${user.id}`, { token: await adminToken(), json: { active: false } });
      await expectEnded(user, browser, apps);
    } finally {
      stopAll(apps);
    }
  });

  test("an admin resetting the password does the same", async () => {
    const user = await createTestUser({ scopes: both });
    const { browser, apps } = await twoApps(user);
    try {
      await call(app, "PATCH", `/admin/users/${user.id}`, { token: await adminToken(), json: { password: "reset-by-admin" } });
      await expectEnded(user, browser, apps);
    } finally {
      stopAll(apps);
    }
  });

  test("changing one's own password does the same", async () => {
    const user = await createTestUser({ scopes: both });
    const { browser, apps } = await twoApps(user);
    try {
      const legacy = await loginOk(app, user);
      const changed = await call(app, "POST", "/auth/change-password", {
        token: legacy.access_token,
        json: { current_password: user.password, new_password: "my-new-password" },
      });
      expect(changed.status).toBe(200);
      await expectEnded(user, browser, apps);
    } finally {
      stopAll(apps);
    }
  });

  test("deleting the account does the same, before its row disappears", async () => {
    const user = await createTestUser({ scopes: both });
    const { apps } = await twoApps(user);
    try {
      const deleted = await call(app, "DELETE", `/admin/users/${user.id}`, { token: await adminToken() });
      expect(deleted.status).toBe(204);
      await eventually(() => apps.every((entry) => entry.stub.hits.length > 0));
      for (const entry of apps) {
        expect((await refreshRequest(app, entry.client, entry.signed.tokens.body.refresh_token)).status).toBe(400);
      }
    } finally {
      stopAll(apps);
    }
  });

  test("removing an app scope ends only that app's tokens, not the sign-in", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const calendar = await signedInApp(browser, user);
    try {
      await call(app, "PATCH", `/admin/users/${user.id}`, { token: await adminToken(), json: { scopes: { calendar: false, tracker: true } } });
      expect((await refreshRequest(app, calendar.client, calendar.signed.tokens.body.refresh_token)).status).toBe(400);
      // still signed in at the OP, so another app they may use needs no password
      const tracker = await registerClient();
      const result = await browser.authorize(tracker, { resource: "urn:legacy:tracker", scope: "openid tracker.read", challenge: pkce().challenge });
      expect(result.redirect?.searchParams.get("code")).toBeString();
    } finally {
      calendar.stub.stop();
    }
  });

  test("another user's sessions are untouched", async () => {
    const victim = await createTestUser({ scopes: both });
    const bystander = await createTestUser({ scopes: both });
    const mine = await twoApps(victim);
    const theirs = await signedInApp(new Browser(app), bystander);
    try {
      await call(app, "PATCH", `/admin/users/${victim.id}`, { token: await adminToken(), json: { active: false } });
      await eventually(() => mine.apps.every((entry) => entry.stub.hits.length > 0));
      expect((await refreshRequest(app, theirs.client, theirs.signed.tokens.body.refresh_token)).status).toBe(200);
      expect(theirs.stub.hits).toHaveLength(0);
    } finally {
      stopAll(mine.apps);
      theirs.stub.stop();
    }
  });
});

describe("session lifetime", () => {
  const NOW = 1_800_000_000;

  test("a session that is not signed in only lives long enough to sign in", () => {
    expect(sessionTtlSeconds({}, NOW)).toBe(3600);
  });

  test("a fresh sign-in gets the idle timeout", () => {
    expect(sessionTtlSeconds({ loginTs: NOW }, NOW)).toBe(config.oidcSessionIdleSeconds);
  });

  test("the idle timeout never carries a session past the absolute one", () => {
    const loginTs = NOW - config.oidcSessionAbsoluteSeconds + 3600; // an hour left
    expect(sessionTtlSeconds({ loginTs }, NOW)).toBe(3600);
  });

  test("a session past its absolute end gets the shortest life there is", () => {
    expect(sessionTtlSeconds({ loginTs: NOW - config.oidcSessionAbsoluteSeconds - 1000 }, NOW)).toBe(1);
  });

  test("defaults are 14 days idle and 30 days absolute", () => {
    expect(config.oidcSessionIdleSeconds).toBe(14 * 86400);
    expect(config.oidcSessionAbsoluteSeconds).toBe(30 * 86400);
  });

  const deadline = async (userId: string) =>
    Number((await testSql`SELECT extract(epoch FROM expires_at)::float AS e FROM oidc_sessions WHERE user_id = ${userId} AND revoked_at IS NULL`)[0].e);

  test("a session that has expired is gone, and takes its refresh tokens with it", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const client = await registerClient();
    const signed = await signInAndRedeem(app, browser, client, user);
    await testSql`UPDATE oidc_sessions SET expires_at = now() - interval '1 second' WHERE user_id = ${user.id}`;
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(400);
    const probe = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(probe.redirect?.searchParams.get("error")).toBe("login_required");
  });

  test("visiting /authorize counts as activity and pushes the idle deadline out", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const client = await registerClient();
    await signInAndRedeem(app, browser, client, user);
    await testSql`UPDATE oidc_sessions SET expires_at = now() + interval '1 hour', payload = jsonb_set(payload, '{exp}', to_jsonb(floor(extract(epoch FROM now() + interval '1 hour'))::bigint)) WHERE user_id = ${user.id}`;
    await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    const extended = await deadline(user.id);
    expect(extended - Date.now() / 1000).toBeGreaterThan(config.oidcSessionIdleSeconds - 60);
  });

  test("using a refresh token counts as activity too, so a busy app is not signed out", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const signed = await signInAndRedeem(app, new Browser(app), client, user);
    await testSql`UPDATE oidc_sessions SET expires_at = now() + interval '1 hour', payload = jsonb_set(payload, '{exp}', to_jsonb(floor(extract(epoch FROM now() + interval '1 hour'))::bigint)) WHERE user_id = ${user.id}`;
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(200);
    await eventually(async () => (await deadline(user.id)) - Date.now() / 1000 > config.oidcSessionIdleSeconds - 60);
    // the library reads the deadline from the payload, so that moved as well
    const [{ exp }] = await testSql`SELECT (payload->>'exp')::bigint AS exp FROM oidc_sessions WHERE user_id = ${user.id}`;
    expect(Number(exp) - Date.now() / 1000).toBeGreaterThan(config.oidcSessionIdleSeconds - 60);
  });

  test("activity never extends a session past its absolute end", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const signed = await signInAndRedeem(app, new Browser(app), client, user);
    // signed in 29 days and 23 hours ago: an hour of absolute lifetime remains
    await testSql`
      UPDATE oidc_sessions
      SET auth_time = now() - make_interval(secs => ${config.oidcSessionAbsoluteSeconds - 3600}),
          expires_at = now() + interval '1 hour'
      WHERE user_id = ${user.id}`;
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(200);
    await sleep(300);
    const remaining = (await deadline(user.id)) - Date.now() / 1000;
    expect(remaining).toBeLessThanOrEqual(3600 + 5);
    expect(remaining).toBeGreaterThan(3000);
  });

  test("a revoked session cannot be revived by activity", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const client = await registerClient();
    const signed = await signInAndRedeem(app, browser, client, user);
    await testSql`UPDATE oidc_sessions SET revoked_at = now() WHERE user_id = ${user.id}`;
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(400);
    const rows = await testSql`SELECT revoked_at FROM oidc_sessions WHERE user_id = ${user.id}`;
    expect(rows[0].revoked_at).not.toBeNull();
  });
});

describe("refresh token reuse", () => {
  test("presenting a rotated token again revokes the grant, descendants included, and is audited", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);

    const second = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(second.status).toBe(200);

    const replay = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    // the thief's replay also kills the legitimate descendant: no silent second session survives
    expect((await refreshRequest(app, client, second.body.refresh_token)).status).toBe(400);

    const event = await eventually(async () => (await testSql`SELECT success, detail FROM auth_events WHERE event = 'oidc.refresh.reuse' AND user_id = ${user.id}`)[0]);
    expect(event.success).toBe(false);
    expect(event.detail).toContain(client.id);
  });

  test("it only costs the app whose token was replayed, not the other apps of the same sign-in", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const victim = await registerClient();
    const other = await registerClient();
    const a = await signInAndRedeem(app, browser, victim, user);
    const b = await signInAndRedeem(app, browser, other, user);
    await refreshRequest(app, victim, a.tokens.body.refresh_token);
    await refreshRequest(app, victim, a.tokens.body.refresh_token); // the replay
    expect((await refreshRequest(app, other, b.tokens.body.refresh_token)).status).toBe(200);
    // and the browser session is still there
    const probe = await browser.authorize(other, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(probe.redirect?.searchParams.get("code")).toBeString();
  });

  test("concurrent refreshes with one token: exactly one wins, the other fails cleanly", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    const results = await Promise.all(Array.from({ length: 4 }, () => refreshRequest(app, client, tokens.body.refresh_token)));
    expect(results.filter((result) => result.status === 200)).toHaveLength(1);
    expect(results.filter((result) => result.status !== 200).every((result) => result.status === 400 || result.status === 500)).toBe(true);
  });
});
