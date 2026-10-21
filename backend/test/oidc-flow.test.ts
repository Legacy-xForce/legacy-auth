import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import jwt from "jsonwebtoken";
import { config } from "../src/config.ts";
import { getJwks } from "../src/keys.ts";
import { call, createTestUser, decode, startApp, verifyWithJwks, type TestApp } from "./helpers.ts";
import {
  Browser,
  ISSUER,
  ISSUER_ORIGIN,
  basicAuth,
  pkce,
  redeem,
  refreshRequest,
  registerClient,
  signInAndRedeem,
  tokenRequest,
  useStubFrontend,
  type TestClient,
} from "./oidc-helpers.ts";

let app: TestApp;
let restoreFrontend: () => void;

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(() => {
  app.stop();
  restoreFrontend();
});

const both = { calendar: true, tracker: true };

describe("discovery", () => {
  let doc: any;
  beforeAll(async () => {
    doc = (await call(app, "GET", "/.well-known/openid-configuration")).body;
  });

  test("describes this issuer and its endpoints", () => {
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER_ORIGIN}/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER_ORIGIN}/token`);
    expect(doc.userinfo_endpoint).toBe(`${ISSUER_ORIGIN}/userinfo`);
    expect(doc.end_session_endpoint).toBe(`${ISSUER_ORIGIN}/logout`);
    expect(doc.jwks_uri).toBe(`${ISSUER_ORIGIN}/.well-known/jwks.json`);
  });

  test("offers only the code flow, S256 and ES256", () => {
    expect(doc.response_types_supported).toEqual(["code"]);
    expect(doc.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["ES256"]);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "none"]);
    expect(doc.subject_types_supported).toEqual(["public"]);
  });

  test("advertises back-channel logout and the scopes and claims it knows", () => {
    expect(doc.backchannel_logout_supported).toBe(true);
    expect(doc.backchannel_logout_session_supported).toBe(true);
    expect(doc.scopes_supported).toEqual(expect.arrayContaining(["openid", "profile", "offline_access", "calendar.read", "calendar.write", "tracker.read", "tracker.write", "admin"]));
    expect(doc.claims_supported).toEqual(expect.arrayContaining(["sub", "sid", "auth_time", "amr", "acr", "preferred_username", "role"]));
  });

  test("does not advertise features that are off", () => {
    expect(doc.registration_endpoint).toBeUndefined();
    expect(doc.introspection_endpoint).toBeUndefined();
    expect(doc.revocation_endpoint).toBeUndefined();
    expect(doc.device_authorization_endpoint).toBeUndefined();
    expect(doc.claims_parameter_supported).toBe(false);
    expect(doc.request_parameter_supported).toBeFalsy();
  });

  test("is cacheable, unlike everything else the OP serves", async () => {
    const response = await call(app, "GET", "/.well-known/openid-configuration");
    expect(response.headers.get("cache-control")).toContain("max-age");
    expect(response.headers.get("cache-control")).not.toContain("no-store");
  });

  test("keeps jwks.json exactly as the legacy service publishes it", async () => {
    const jwks = (await call(app, "GET", "/.well-known/jwks.json")).body;
    expect(jwks).toEqual(getJwks());
  });
});

describe("authorization code + PKCE, end to end, from discovery alone", () => {
  test("a client that knows only the issuer completes a sign-in", async () => {
    const user = await createTestUser({ role: "admin", scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);

    // everything below uses URLs read from the discovery document
    const doc = (await call(app, "GET", "/.well-known/openid-configuration")).body;
    const { verifier, challenge } = pkce();
    const query = new URLSearchParams({
      client_id: client.id,
      redirect_uri: client.redirect,
      response_type: "code",
      scope: "openid profile calendar.read calendar.write offline_access",
      resource: "urn:legacy:calendar",
      prompt: "consent",
      code_challenge: challenge,
      code_challenge_method: doc.code_challenge_methods_supported[0],
      state: "abc",
      nonce: "n-0S6_WzA2Mj",
    });
    let step = await browser.follow(await browser.request(`${doc.authorization_endpoint}?${query}`), client.redirect);
    expect(step.interaction).toBeDefined();
    step = await browser.signIn(step.interaction!, user, client);
    expect(step.redirect?.searchParams.get("state")).toBe("abc");

    const response = await tokenRequest(
      app,
      { grant_type: "authorization_code", code: step.redirect!.searchParams.get("code")!, redirect_uri: client.redirect, code_verifier: verifier },
      basicAuth(client.id, client.secret!)
    );
    expect(response.status).toBe(200);
    expect(response.body.token_type).toBe("Bearer");
    expect(response.body.expires_in).toBe(config.accessTokenTtlSeconds);
    expect(response.body.refresh_token).toBeString();

    const idToken = verifyWithJwks(response.body.id_token, { issuer: ISSUER, audience: client.id });
    expect(idToken.sub).toBe(user.id);
    expect(idToken.nonce).toBe("n-0S6_WzA2Mj");

    // the userinfo endpoint named in discovery works with a token that is not tied to a resource
    const second = pkce();
    const noResource = await browser.authorize(client, { scope: "openid profile", resource: null, prompt: "login", challenge: second.challenge });
    const signedIn = await browser.signIn(noResource.interaction!, user, client);
    const opToken = await redeem(app, client, signedIn.redirect!, second.verifier);
    const userinfo = await call(app, "GET", "/userinfo", { token: opToken.body.access_token });
    expect(userinfo.status).toBe(200);
    expect(userinfo.body).toEqual({ sub: user.id, preferred_username: user.username, role: "admin" });
  });
});

describe("tokens", () => {
  let user: Awaited<ReturnType<typeof createTestUser>>;
  let client: TestClient;
  let issued: Awaited<ReturnType<typeof signInAndRedeem>>;

  beforeAll(async () => {
    user = await createTestUser({ role: "admin", scopes: { calendar: true, tracker: false } });
    client = await registerClient();
    issued = await signInAndRedeem(app, new Browser(app), client, user, { nonce: "the-nonce" });
  });

  test("the access token is an RFC 9068 JWT signed with the service's existing key", () => {
    const { header, payload } = decode(issued.tokens.body.access_token) as { header: any; payload: any };
    expect(header).toMatchObject({ alg: "ES256", typ: "at+jwt", kid: getJwks().keys[0].kid });
    expect(payload.iss).toBe(ISSUER);
    expect(payload.aud).toBe("calendar");
    expect(payload.client_id).toBe(client.id);
    expect(payload.sub).toBe(user.id);
    expect(payload.scope).toBe("calendar.read calendar.write");
    expect(payload.jti).toBeString();
    expect(payload.exp - payload.iat).toBe(config.accessTokenTtlSeconds);
    expect(payload.sid).toBeString();
  });

  test("it verifies against the published JWKS, like any other token of this service", () => {
    const claims = verifyWithJwks(issued.tokens.body.access_token, { issuer: ISSUER, audience: "calendar" });
    expect(claims.sub).toBe(user.id);
  });

  test("it carries the legacy claims the resource servers read today", () => {
    const claims = verifyWithJwks(issued.tokens.body.access_token) as any;
    expect(claims.type).toBe("access");
    expect(claims.username).toBe(user.username);
    expect(claims.role).toBe("admin");
    expect(claims.scopes).toEqual({ calendar: true, tracker: false });
  });

  test("a resource server's own checks accept it (issuer, token type, audience, scope)", () => {
    // the checks calendar and tracker apply since Phase 0, written out as they apply them
    const claims = verifyWithJwks(issued.tokens.body.access_token, { issuer: ISSUER }) as any;
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    expect(claims.type === "access" && audiences.includes("calendar") && claims.scopes?.calendar === true).toBe(true);
    expect(claims.type === "access" && audiences.includes("tracker") && claims.scopes?.tracker === true).toBe(false);
  });

  test("a calendar token is not a tracker token (cross-app replay stays refused)", () => {
    expect(() => verifyWithJwks(issued.tokens.body.access_token, { audience: "tracker" })).toThrow(/audience invalid/);
  });

  test("the ID token holds identity and authentication facts, and no role or scopes", () => {
    const claims = verifyWithJwks(issued.tokens.body.id_token, { issuer: ISSUER, audience: client.id }) as any;
    expect(claims).toMatchObject({ sub: user.id, nonce: "the-nonce", amr: ["pwd"], acr: "urn:legacy:loa:1" });
    expect(claims.auth_time).toBeNumber();
    expect(claims.sid).toBeString();
    expect(claims.sid).toBe((decode(issued.tokens.body.access_token).payload as any).sid);
    expect(claims.role).toBeUndefined();
    expect(claims.scopes).toBeUndefined();
    expect(claims.scope).toBeUndefined();
    expect(claims.username).toBeUndefined();
    expect(decode(issued.tokens.body.id_token).header).toMatchObject({ alg: "ES256", kid: getJwks().keys[0].kid });
  });

  test("the redirect carries a code, the state and the issuer, and never a token", () => {
    const params = [...issued.redirect.searchParams.keys()].sort();
    expect(params).toEqual(["code", "iss", "state"]);
    expect(issued.redirect.hash).toBe("");
    expect(issued.redirect.toString()).not.toContain("access_token");
    expect(issued.redirect.searchParams.get("iss")).toBe(ISSUER);
  });

  test("token responses are never cached", () => {
    expect(issued.tokens.headers.get("cache-control")).toContain("no-store");
    expect(issued.tokens.headers.get("pragma")).toBe("no-cache");
  });
});

describe("sign-in rules", () => {
  test("a user without the app's scope is refused with access_denied, not given a token", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: false } });
    const client = await registerClient();
    const { challenge } = pkce();
    const result = await new Browser(app).flow(client, user, { resource: "urn:legacy:tracker", scope: "openid tracker.read offline_access", challenge });
    expect(result.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(result.redirect?.searchParams.get("code")).toBeNull();
    expect(result.redirect?.searchParams.get("error_description")).toContain("no access to tracker");
  });

  test("only admins get the admin scope", async () => {
    const plain = await createTestUser({ scopes: both });
    const admin = await createTestUser({ role: "admin" });
    const client = await registerClient({ allowed_scopes: ["openid", "profile", "admin", "offline_access"] });
    const denied = await new Browser(app).flow(client, plain, { resource: null, scope: "openid admin", challenge: pkce().challenge });
    expect(denied.redirect?.searchParams.get("error")).toBe("access_denied");
    const granted = await new Browser(app).flow(client, admin, { resource: null, scope: "openid admin", challenge: pkce().challenge });
    expect(granted.redirect?.searchParams.get("code")).toBeString();
  });

  test("a client only gets the scopes it is registered for", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ allowed_scopes: ["openid", "calendar.read"] });
    const { verifier, challenge } = pkce();
    const result = await new Browser(app).flow(client, user, { scope: "openid calendar.read", challenge });
    const tokens = await redeem(app, client, result.redirect!, verifier);
    expect(verifyWithJwks(tokens.body.access_token).scope).toBe("calendar.read");
  });

  test("a client cannot reach an app none of its scopes belong to", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ allowed_scopes: ["openid", "calendar.read"] });
    const result = await new Browser(app).flow(client, user, { resource: "urn:legacy:tracker", scope: "openid", challenge: pkce().challenge });
    expect(result.redirect?.searchParams.get("error")).toBe("invalid_target");
  });

  test("an unknown resource is invalid_target, not a server error", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const result = await new Browser(app).flow(client, user, { resource: "urn:legacy:mail", challenge: pkce().challenge });
    expect(result.redirect?.searchParams.get("error")).toBe("invalid_target");
  });

  test("a wrong password does not finish the interaction, and a right one afterwards does", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge });
    const wrong = await browser.interactionCall(start.interaction!.uid, "login", { username: user.username, password: "nope" });
    expect(wrong.status).toBe(401);
    expect(wrong.body.redirect).toBeUndefined();
    const right = await browser.signIn(start.interaction!, user, client);
    expect(right.redirect?.searchParams.get("code")).toBeString();
  });

  test("a disabled account cannot sign in", async () => {
    const user = await createTestUser({ scopes: both, active: false });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge });
    const result = await browser.interactionCall(start.interaction!.uid, "login", { username: user.username, password: user.password });
    expect(result.status).toBe(403);
  });

  test("login_hint reaches the sign-in page, which can pre-fill the username", async () => {
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge, extra: { login_hint: "alice" } });
    const response = await browser.request(`${ISSUER_ORIGIN}/interaction/${start.interaction!.uid}/details`);
    const details = await response.json();
    expect(details).toMatchObject({ prompt: "login", login_hint: "alice", client: { id: client.id } });
  });
});

describe("single sign-on", () => {
  test("a second app gets a code without a login form, with its own audience and sid", async () => {
    const user = await createTestUser({ scopes: both });
    const calendar = await registerClient();
    const tracker = await registerClient();
    const browser = new Browser(app);

    const first = await signInAndRedeem(app, browser, calendar, user);
    const second = pkce();
    const result = await browser.authorize(tracker, { resource: "urn:legacy:tracker", scope: "openid tracker.read offline_access", challenge: second.challenge });
    expect(result.interaction).toBeUndefined();
    expect(result.redirect?.searchParams.get("code")).toBeString();

    const tokens = await redeem(app, tracker, result.redirect!, second.verifier);
    const trackerClaims = verifyWithJwks(tokens.body.access_token, { audience: "tracker" }) as any;
    expect(trackerClaims.sub).toBe(user.id);
    expect(trackerClaims.client_id).toBe(tracker.id);
    expect(() => verifyWithJwks(tokens.body.access_token, { audience: "calendar" })).toThrow();
    // each app has its own session id, so one app's logout token cannot be mistaken for another's
    expect(trackerClaims.sid).not.toBe((decode(first.tokens.body.access_token).payload as any).sid);
  });

  test("prompt=none succeeds with a session and answers login_required without one", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);

    const none = await new Browser(app).authorize(client, { prompt: "none", challenge: pkce().challenge });
    expect(none.redirect?.searchParams.get("error")).toBe("login_required");

    await signInAndRedeem(app, browser, client, user);
    const silent = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(silent.redirect?.searchParams.get("code")).toBeString();
  });

  test("a web app developed against http://localhost can do prompt=none too", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ redirect_uris: ["http://localhost:4100/callback"], post_logout_redirect_uris: ["http://localhost:4100/"] });
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user);
    const silent = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(silent.redirect?.searchParams.get("code")).toBeString();
  });

  test("the mobile app cannot: a native client always goes through the browser", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ is_public: true, redirect_uris: ["com.legacy.silent:/cb"], allowed_scopes: ["openid", "tracker.read", "tracker.write"] });
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user, { resource: "urn:legacy:tracker", scope: "openid tracker.read", prompt: "consent" });
    const silent = await browser.authorize(client, { prompt: "none", resource: "urn:legacy:tracker", challenge: pkce().challenge, scope: "openid tracker.read" });
    expect(silent.redirect?.searchParams.get("error")).toBe("interaction_required");
    expect(silent.redirect?.searchParams.get("code")).toBeNull();
  });

  test("prompt=login asks again even with a session", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user);
    const again = await browser.authorize(client, { prompt: "login", challenge: pkce().challenge });
    expect(again.interaction).toBeDefined();
  });

  test("max_age forces a new sign-in once the session is older than that", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user);
    // the library compares whole seconds, so the session has to be more than one second older
    await new Promise((resolve) => setTimeout(resolve, 2200));
    const stale = await browser.authorize(client, { prompt: null, challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write", extra: { max_age: "1" } });
    expect(stale.interaction).toBeDefined();
  });

  test("the sign-in of one browser is invisible to another", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    await signInAndRedeem(app, new Browser(app), client, user);
    const other = await new Browser(app).authorize(client, { challenge: pkce().challenge });
    expect(other.interaction).toBeDefined();
  });
});

describe("public clients (mobile)", () => {
  test("PKCE with a custom-scheme redirect, no secret, and refresh", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ is_public: true, redirect_uris: ["com.legacy.test:/oauth2redirect"], allowed_scopes: ["openid", "profile", "tracker.read", "tracker.write", "offline_access"] });
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user, { resource: "urn:legacy:tracker", scope: "openid profile tracker.read offline_access" });
    expect(tokens.status).toBe(200);
    expect(verifyWithJwks(tokens.body.access_token, { audience: "tracker" }).client_id).toBe(client.id);

    const refreshed = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(tokens.body.refresh_token);
  });

  test("a public client cannot use a secret-based method, and needs no secret", async () => {
    const client = await registerClient({ is_public: true, redirect_uris: ["com.legacy.test2:/cb"] });
    expect(client.secret).toBeNull();
    const result = await tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50), client_id: client.id });
    expect(result.status).toBe(400); // reached the grant check: authentication as a public client succeeded
    expect(result.body.error).toBe("invalid_grant");
  });
});

describe("refresh", () => {
  test("rotates, keeps the audience, and re-reads the user's scopes", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: false } });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);

    const refreshed = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(tokens.body.refresh_token);
    const claims = verifyWithJwks(refreshed.body.access_token, { audience: "calendar" }) as any;
    expect(claims).toMatchObject({ sub: user.id, role: "user", type: "access", scopes: { calendar: true, tracker: false } });
  });

  test("losing the app's scope ends the session for that app", async () => {
    const user = await createTestUser({ scopes: { calendar: true, tracker: true } });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    const { testSql } = await import("./helpers.ts");
    await testSql`UPDATE users SET scopes = '{"calendar": false, "tracker": true}'::jsonb WHERE id = ${user.id}`;
    const refreshed = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(refreshed.status).toBe(400);
    expect(refreshed.body.error).toBe("invalid_grant");
  });

  test("a disabled account cannot refresh", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    const { testSql } = await import("./helpers.ts");
    await testSql`UPDATE users SET active = false WHERE id = ${user.id}`;
    expect((await refreshRequest(app, client, tokens.body.refresh_token)).status).toBe(400);
  });

  test("a refresh token issued to one client is useless to another", async () => {
    const user = await createTestUser({ scopes: both });
    const a = await registerClient();
    const b = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), a, user);
    const stolen = await refreshRequest(app, b, tokens.body.refresh_token);
    expect(stolen.status).toBe(400);
    // and the owner is unaffected by the attempt
    expect((await refreshRequest(app, a, tokens.body.refresh_token)).status).toBe(200);
  });
});

describe("the legacy login keeps working beside the OP", () => {
  test("/auth/login and /auth/refresh are unaffected", async () => {
    const user = await createTestUser({ scopes: both });
    const login = await call(app, "POST", "/auth/login", { json: { username: user.username, password: user.password, audience: "calendar" } });
    expect(login.status).toBe(200);
    const claims = jwt.decode(login.body.access_token) as any;
    expect(claims.aud).toEqual(["calendar"]);
    expect((await call(app, "POST", "/auth/refresh", { json: { refresh_token: login.body.refresh_token } })).status).toBe(200);
  });

  test("an OP access token is accepted by this service's own authenticated endpoints", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    const me = await call(app, "GET", "/auth/me", { token: tokens.body.access_token });
    expect(me.status).toBe(200);
    expect(me.body.username).toBe(user.username);
  });
});
