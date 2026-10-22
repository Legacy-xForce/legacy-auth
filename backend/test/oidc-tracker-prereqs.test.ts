import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { call, createTestUser, decode, loginOk, startApp, testSql, type TestApp } from "./helpers.ts";
import {
  Browser,
  pkce,
  redeem,
  refreshRequest,
  registerClient,
  startBackchannelStub,
  useStubFrontend,
  type TestClient,
} from "./oidc-helpers.ts";

// What the tracker needs from Legacy Auth before it can move to the OpenID Provider (legacy-auth#8):
// a sign-in that works for a user without a calendar, defaults for clients that cannot name two
// resources, native apps that outlive the phone browser's session, and logout when access is lost.

let app: TestApp;
let restoreFrontend: () => void;
const original = { internal: config.oidcAllowInternalBackchannel };

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(async () => {
  await new Promise((resolve) => setTimeout(resolve, 100));
  app.stop();
  restoreFrontend();
});
afterEach(() => {
  config.oidcAllowInternalBackchannel = original.internal;
});

const TRACKER = "urn:legacy:tracker";
const CALENDAR = "urn:legacy:calendar";
const SCOPES = "openid profile tracker.read tracker.write calendar.read offline_access";
const SCOPES_FOR_CLIENT = ["openid", "profile", "tracker.read", "tracker.write", "calendar.read", "offline_access"];
const both = { calendar: true, tracker: true };
const trackerOnly = { calendar: false, tracker: true };

const claimsOf = (token: string) => decode(token).payload as any;

/** A client set up as the tracker's are: tracker first, the calendar's read scope on top. */
const trackerClient = (overrides: Parameters<typeof registerClient>[0] = {}) =>
  registerClient({ allowed_scopes: SCOPES_FOR_CLIENT, primary_resource: TRACKER, default_resources: [TRACKER, CALENDAR], ...overrides });
const nativeClient = () => trackerClient({ is_public: true, redirect_uris: ["com.legacy.test:/oauth2redirect"] });

async function signIn(client: TestClient, user: Awaited<ReturnType<typeof createTestUser>>, options: { resource?: string | string[] | null; scope?: string } = {}) {
  const { verifier, challenge } = pkce();
  const browser = new Browser(app);
  const result = await browser.flow(client, user, { resource: options.resource, scope: options.scope ?? SCOPES, challenge });
  return { browser, result, verifier };
}

describe("a client with a primary resource", () => {
  test("a user without the calendar still signs in, for the tracker alone", async () => {
    const client = await trackerClient();
    const user = await createTestUser({ scopes: trackerOnly });
    const { result, verifier } = await signIn(client, user, { resource: [TRACKER, CALENDAR] });
    expect(result.redirect?.searchParams.get("error")).toBeNull();
    const tokens = await redeem(app, client, result.redirect!, verifier, TRACKER);
    expect(tokens.status).toBe(200);
    expect(claimsOf(tokens.body.access_token)).toMatchObject({ aud: "tracker", scope: "tracker.read tracker.write" });
  });

  test("asking that user for a calendar token is refused without costing the session", async () => {
    const client = await trackerClient();
    const user = await createTestUser({ scopes: trackerOnly });
    const { result, verifier } = await signIn(client, user, { resource: [TRACKER, CALENDAR] });
    const first = await redeem(app, client, result.redirect!, verifier, TRACKER);

    const refused = await refreshRequest(app, client, first.body.refresh_token, CALENDAR);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");

    const next = await refreshRequest(app, client, first.body.refresh_token, TRACKER);
    expect(next.status).toBe(200);
    expect(claimsOf(next.body.access_token).aud).toBe("tracker");
  });

  test("a user who loses the calendar later is refused the same way, and the tracker carries on", async () => {
    const client = await trackerClient();
    const user = await createTestUser({ scopes: both });
    const { result, verifier } = await signIn(client, user, { resource: [TRACKER, CALENDAR] });
    const first = await redeem(app, client, result.redirect!, verifier, TRACKER);
    await testSql`UPDATE users SET scopes = '{"calendar": false, "tracker": true}'::jsonb WHERE id = ${user.id}`;

    const refused = await refreshRequest(app, client, first.body.refresh_token, CALENDAR);
    expect(refused.body.error).toBe("invalid_target");
    const next = await refreshRequest(app, client, first.body.refresh_token, TRACKER);
    expect(next.status).toBe(200);
    expect(claimsOf(next.body.access_token).scopes).toEqual(trackerOnly);
  });

  test("a user without the tracker is still turned away", async () => {
    const client = await trackerClient();
    const { result } = await signIn(client, await createTestUser({ scopes: { calendar: true, tracker: false } }), { resource: [TRACKER, CALENDAR] });
    expect(result.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(result.redirect?.searchParams.get("error_description")).toContain("no access to tracker");
    expect(result.redirect?.searchParams.get("code")).toBeNull();
  });

  test("without a primary resource every requested app is still required", async () => {
    const client = await registerClient({ allowed_scopes: SCOPES_FOR_CLIENT });
    const { result } = await signIn(client, await createTestUser({ scopes: trackerOnly }), { resource: [TRACKER, CALENDAR] });
    expect(result.redirect?.searchParams.get("error")).toBe("access_denied");
  });

  test("the code covers both apps for a user who has both, and a refresh without a resource gets the main one", async () => {
    const client = await trackerClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: both }), { resource: [TRACKER, CALENDAR] });
    // redeeming without naming an app is not a guess for a client with a main app
    const first = await redeem(app, client, result.redirect!, verifier);
    expect(first.status).toBe(200);
    expect(claimsOf(first.body.access_token).aud).toBe("tracker");
    const unnamed = await refreshRequest(app, client, first.body.refresh_token);
    expect(unnamed.status).toBe(200);
    expect(claimsOf(unnamed.body.access_token).aud).toBe("tracker");
    const calendar = await refreshRequest(app, client, unnamed.body.refresh_token, CALENDAR);
    expect(calendar.status).toBe(200);
    expect(claimsOf(calendar.body.access_token)).toMatchObject({ aud: "calendar", scope: "calendar.read" });
  });
});

describe("a refresh that cannot work keeps the refresh token", () => {
  test("naming no app, or two, on a grant for two apps with no main one", async () => {
    const client = await registerClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: both }), { resource: [TRACKER, CALENDAR], scope: "openid profile tracker.read calendar.read offline_access" });
    const first = await redeem(app, client, result.redirect!, verifier, TRACKER);
    expect(first.status).toBe(200);

    const unnamed = await refreshRequest(app, client, first.body.refresh_token);
    expect(unnamed.body.error).toBe("invalid_target");
    const twice = await call(app, "POST", "/token", {
      form: { grant_type: "refresh_token", refresh_token: first.body.refresh_token, client_id: client.id } as Record<string, string>,
    });
    expect(twice.status).toBe(401);

    const named = await refreshRequest(app, client, first.body.refresh_token, CALENDAR);
    expect(named.status).toBe(200);
  });
});

describe("default resources", () => {
  test("a request that names none gets the client's, limited to the apps whose scopes it asked for", async () => {
    const client = await nativeClient();
    const user = await createTestUser({ scopes: both });

    const all = await signIn(client, user, { resource: null });
    const first = await redeem(app, client, all.result.redirect!, all.verifier, TRACKER);
    expect(first.status).toBe(200);
    const calendar = await refreshRequest(app, client, first.body.refresh_token, CALENDAR);
    expect(calendar.status).toBe(200);
    expect(claimsOf(calendar.body.access_token)).toMatchObject({ aud: "calendar", scope: "calendar.read" });

    const trackerScopesOnly = await signIn(client, user, { resource: null, scope: "openid profile tracker.read tracker.write offline_access" });
    const tracker = await redeem(app, client, trackerScopesOnly.result.redirect!, trackerScopesOnly.verifier);
    expect(tracker.status).toBe(200);
    const notAsked = await refreshRequest(app, client, tracker.body.refresh_token, CALENDAR);
    expect(notAsked.body.error).toBe("invalid_target");
  });

  test("a user without the calendar signs in with the defaults too", async () => {
    const client = await nativeClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: trackerOnly }), { resource: null });
    const tokens = await redeem(app, client, result.redirect!, verifier);
    expect(tokens.status).toBe(200);
    expect(claimsOf(tokens.body.access_token)).toMatchObject({ aud: "tracker", scope: "tracker.read tracker.write" });
  });

  test("a client without defaults is not given any", async () => {
    const client = await registerClient();
    const { result } = await signIn(client, await createTestUser({ scopes: both }), { resource: null, scope: "openid profile tracker.read offline_access" });
    // no resource: the app scopes are dropped and the client gets an identity-only sign-in
    expect(result.redirect?.searchParams.get("code")).toBeString();
  });
});

describe("a native app", () => {
  const refreshTokenOf = async (userId: string) => {
    const [row] = await testSql`SELECT payload, expires_at FROM oidc_payloads WHERE model = 'RefreshToken' AND payload->>'accountId' = ${userId} ORDER BY expires_at DESC LIMIT 1`;
    return row;
  };
  const grantOf = async (userId: string) => {
    const [row] = await testSql`SELECT expires_at FROM oidc_payloads WHERE model = 'Grant' AND payload->>'accountId' = ${userId} ORDER BY expires_at DESC LIMIT 1`;
    return row;
  };
  const daysFromNow = (value: string) => (new Date(value).getTime() - Date.now()) / 86_400_000;

  test("its refresh token is unused-for 30 days and its grant ends 180 days after sign-in", async () => {
    const client = await nativeClient();
    const user = await createTestUser({ scopes: both });
    const { result, verifier } = await signIn(client, user, { resource: null });
    const tokens = await redeem(app, client, result.redirect!, verifier, TRACKER);
    expect(tokens.status).toBe(200);

    expect(daysFromNow((await refreshTokenOf(user.id)).expires_at)).toBeCloseTo(30, 0);
    expect(daysFromNow((await grantOf(user.id)).expires_at)).toBeCloseTo(180, 0);
    // a refresh gives the token a new 30 days, and does not move the end of the grant
    const grantEnd = (await grantOf(user.id)).expires_at;
    await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
    expect(new Date((await grantOf(user.id)).expires_at).getTime()).toBe(new Date(grantEnd).getTime());
  });

  test("a web client's grant and refresh token keep their 30 days", async () => {
    const client = await trackerClient();
    const user = await createTestUser({ scopes: both });
    const { result, verifier } = await signIn(client, user, { resource: [TRACKER, CALENDAR] });
    await redeem(app, client, result.redirect!, verifier, TRACKER);
    expect(daysFromNow((await refreshTokenOf(user.id)).expires_at)).toBeCloseTo(30, 0);
    expect(daysFromNow((await grantOf(user.id)).expires_at)).toBeCloseTo(30, 0);
  });

  test("it stays signed in when the browser session ends, a web app does not", async () => {
    const user = await createTestUser({ scopes: both });
    const native = await nativeClient();
    const web = await trackerClient();
    const a = await signIn(native, user, { resource: null });
    const nativeTokens = await redeem(app, native, a.result.redirect!, a.verifier, TRACKER);
    const b = await signIn(web, user, { resource: [TRACKER, CALENDAR] });
    const webTokens = await redeem(app, web, b.result.redirect!, b.verifier, TRACKER);

    // the user signs out in the phone's browser: every OP session is gone
    await testSql`UPDATE oidc_sessions SET revoked_at = now() WHERE user_id = ${user.id}`;

    const kept = await refreshRequest(app, native, nativeTokens.body.refresh_token, TRACKER);
    expect(kept.status).toBe(200);
    const ended = await refreshRequest(app, web, webTokens.body.refresh_token, TRACKER);
    expect(ended.status).toBe(400);
    expect(ended.body.error).toBe("invalid_grant");
  });
});

describe("back-channel logout for public clients", () => {
  const withStub = async (scopes: typeof both) => {
    config.oidcAllowInternalBackchannel = true;
    const stub = await startBackchannelStub();
    const client = await trackerClient({ is_public: true, redirect_uris: ["https://tracker.test.local/callback"], post_logout_redirect_uris: [], backchannel_logout_uri: stub.url });
    const user = await createTestUser({ scopes });
    const { result, verifier } = await signIn(client, user, { resource: [TRACKER, CALENDAR] });
    const tokens = await redeem(app, client, result.redirect!, verifier, TRACKER);
    expect(tokens.status).toBe(200);
    const admin = await loginOk(app, await createTestUser({ role: "admin" }));
    const setScopes = (scopes: typeof both) => call(app, "PATCH", `/admin/users/${user.id}`, { token: admin.access_token, json: { scopes } });
    return { stub, client, user, tokens, setScopes };
  };
  const waitFor = async (condition: () => boolean) => {
    for (let i = 0; i < 50 && !condition(); i++) await new Promise((resolve) => setTimeout(resolve, 50));
  };

  test("a logout token is sent, and the grant ended, when the tracker scope is removed", async () => {
    const { stub, client, user, tokens, setScopes } = await withStub(both);
    try {
      expect((await setScopes({ calendar: true, tracker: false })).status).toBe(200);
      await waitFor(() => stub.hits.length > 0);
      expect(stub.hits).toHaveLength(1);
      const logoutToken = decode(new URLSearchParams(stub.hits[0].body).get("logout_token")!).payload as any;
      expect(logoutToken).toMatchObject({ sub: user.id, aud: client.id });
      expect(logoutToken.sid).toBeString();
      const refused = await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
      expect(refused.status).toBe(400);
    } finally {
      stub.stop();
    }
  });

  test("losing only the calendar sends nothing: the tracker does not need it", async () => {
    const { stub, client, tokens, setScopes } = await withStub(both);
    try {
      expect((await setScopes(trackerOnly)).status).toBe(200);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(stub.hits).toHaveLength(0);
      const next = await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
      expect(next.status).toBe(200);
    } finally {
      stub.stop();
    }
  });

  test("disabling the account sends one too", async () => {
    const { stub, user } = await withStub(both);
    try {
      const admin = await loginOk(app, await createTestUser({ role: "admin" }));
      await call(app, "PATCH", `/admin/users/${user.id}`, { token: admin.access_token, json: { active: false } });
      await waitFor(() => stub.hits.length > 0);
      expect(stub.hits).toHaveLength(1);
    } finally {
      stub.stop();
    }
  });
});

describe("CORS for a public browser client", () => {
  const origin = "https://tracker.legacy-group.tech";

  test("the token endpoint and the discovery document can be called from the app's origin", async () => {
    const client = await trackerClient({ is_public: true, redirect_uris: [`${origin}/callback`], post_logout_redirect_uris: [] });

    const discovery = await call(app, "GET", "/.well-known/openid-configuration", { headers: { origin } });
    expect(discovery.status).toBe(200);
    expect(discovery.headers.get("access-control-allow-origin")).toBeOneOf([origin, "*"]);

    const preflight = await call(app, "OPTIONS", "/token", {
      headers: { origin, "access-control-request-method": "POST", "access-control-request-headers": "content-type" },
    });
    expect(preflight.status).toBeLessThan(300);
    expect(preflight.headers.get("access-control-allow-origin")).toBeOneOf([origin, "*"]);

    const token = await call(app, "POST", "/token", { headers: { origin }, form: { grant_type: "refresh_token", refresh_token: "nope", client_id: client.id } });
    expect(token.status).toBe(400);
    const allowed = token.headers.get("access-control-allow-origin");
    expect(allowed).toBeOneOf([origin, "*"]);
    // one value, not "origin, origin" from two layers
    expect(allowed!.includes(",")).toBe(false);
  });

  test("an origin that is none of the client's redirect URIs is refused", async () => {
    const client = await trackerClient({ is_public: true, redirect_uris: [`${origin}/callback`], post_logout_redirect_uris: [] });
    const token = await call(app, "POST", "/token", {
      headers: { origin: "https://evil.example" },
      form: { grant_type: "refresh_token", refresh_token: "nope", client_id: client.id },
    });
    expect(token.status).toBe(400);
    expect(token.body.error_description).toContain("not allowed for client");
    expect(token.headers.get("access-control-allow-origin")).toBeNull();
  });
});
