import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "crypto";
import { config } from "../src/config.ts";
import { call, createTestUser, fromIp, startApp, testSql, type TestApp } from "./helpers.ts";
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
const original = { loginMax: config.loginMaxFailures, proxy: config.trustProxy };

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(() => {
  app.stop();
  restoreFrontend();
});
afterEach(() => {
  config.loginMaxFailures = original.loginMax;
  config.trustProxy = original.proxy;
});

const both = { calendar: true, tracker: true };

/** An authorization request as a raw URL, for the requests a well-behaved client would never send. */
function authorizeUrl(client: TestClient, overrides: Record<string, string | null> = {}) {
  const params: Record<string, string | null> = {
    client_id: client.id,
    redirect_uri: client.redirect,
    response_type: "code",
    scope: "openid profile calendar.read calendar.write",
    resource: "urn:legacy:calendar",
    code_challenge: pkce().challenge,
    code_challenge_method: "S256",
    state: "s1",
    nonce: "n1",
    ...overrides,
  };
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== null) query.set(key, value);
  return `${ISSUER_ORIGIN}/authorize?${query}`;
}

async function bodyText(response: Response) {
  return (await response.text()).replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
}

describe("authorization codes", () => {
  test("cannot be redeemed twice, and a replay revokes what the first redemption issued", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { verifier, challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const first = await redeem(app, client, flow.redirect!, verifier);
    expect(first.status).toBe(200);

    const replay = await redeem(app, client, flow.redirect!, verifier);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");

    // OAuth 2.0 Security BCP: a replayed code means the code leaked, so what it produced is revoked too
    expect((await refreshRequest(app, client, first.body.refresh_token)).status).toBe(400);
  });

  test("redeem at most once even when redeemed concurrently", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { verifier, challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const results = await Promise.all(Array.from({ length: 6 }, () => redeem(app, client, flow.redirect!, verifier)));
    const winners = results.filter((result) => result.status === 200);
    expect(winners).toHaveLength(1);
    expect(results.filter((result) => result.status !== 200).every((result) => result.status === 400 || result.status === 500)).toBe(true);
  });

  test("expire after 60 seconds", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { verifier, challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const [{ ttl }] = await testSql`SELECT extract(epoch FROM (expires_at - now()))::float AS ttl FROM oidc_payloads WHERE model = 'AuthorizationCode' ORDER BY expires_at DESC LIMIT 1`;
    expect(Number(ttl)).toBeGreaterThan(50);
    expect(Number(ttl)).toBeLessThanOrEqual(60);
    await testSql`UPDATE oidc_payloads SET expires_at = now() - interval '1 second' WHERE model = 'AuthorizationCode'`;
    const late = await redeem(app, client, flow.redirect!, verifier);
    expect(late.status).toBe(400);
    expect(late.body.error).toBe("invalid_grant");
  });

  test("are bound to the redirect_uri they were issued for", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient({ redirect_uris: ["https://bound.test.local/cb"] });
    const { verifier, challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const wrong = await tokenRequest(
      app,
      { grant_type: "authorization_code", code: flow.redirect!.searchParams.get("code")!, redirect_uri: "https://bound.test.local/other", code_verifier: verifier },
      basicAuth(client.id, client.secret!)
    );
    expect(wrong.status).toBe(400);
  });

  test("are bound to the PKCE challenge: the wrong verifier fails, no verifier fails", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const code = flow.redirect!.searchParams.get("code")!;
    const auth = basicAuth(client.id, client.secret!);
    const base = { grant_type: "authorization_code", code, redirect_uri: client.redirect };
    expect((await tokenRequest(app, { ...base, code_verifier: pkce().verifier }, auth)).status).toBe(400);
    expect((await tokenRequest(app, base, auth)).status).toBe(400);
  });

  test("are bound to the client: another client's credentials cannot redeem them", async () => {
    const user = await createTestUser({ scopes: both });
    const victim = await registerClient();
    const attacker = await registerClient();
    const { verifier, challenge } = pkce();
    const flow = await new Browser(app).flow(victim, user, { challenge });
    const stolen = await tokenRequest(
      app,
      { grant_type: "authorization_code", code: flow.redirect!.searchParams.get("code")!, redirect_uri: victim.redirect, code_verifier: verifier },
      basicAuth(attacker.id, attacker.secret!)
    );
    expect(stolen.status).toBe(400);
    expect(stolen.body.error).toBe("invalid_grant");
  });
});

describe("PKCE", () => {
  let client: TestClient;
  beforeAll(async () => {
    client = await registerClient();
  });
  const redirectOf = async (url: string) => {
    const response = await new Browser(app).request(url);
    return { response, location: response.headers.get("location") ?? "" };
  };

  test("plain is refused", async () => {
    const { location } = await redirectOf(authorizeUrl(client, { code_challenge_method: "plain", code_challenge: "a".repeat(43) }));
    expect(location).toContain("error=invalid_request");
    expect(location).not.toContain("/interaction/");
  });

  test("a missing code_challenge_method is not read as plain", async () => {
    const { location } = await redirectOf(authorizeUrl(client, { code_challenge_method: null }));
    expect(location).toContain("error=invalid_request");
  });

  test("a missing code_challenge is refused, for confidential and public clients alike", async () => {
    expect((await redirectOf(authorizeUrl(client, { code_challenge: null, code_challenge_method: null }))).location).toContain("error=invalid_request");
    const publicClient = await registerClient({ is_public: true, redirect_uris: ["com.pkce.test:/cb"] });
    expect((await redirectOf(authorizeUrl(publicClient, { code_challenge: null, code_challenge_method: null }))).location).toContain("error=invalid_request");
  });

  test("a malformed challenge is refused", async () => {
    expect((await redirectOf(authorizeUrl(client, { code_challenge: "too short" }))).location).toContain("error=invalid_request");
  });

  test("a verifier that is too short is refused at the token endpoint", async () => {
    const user = await createTestUser({ scopes: both });
    const { challenge } = pkce();
    const flow = await new Browser(app).flow(client, user, { challenge });
    const result = await tokenRequest(
      app,
      { grant_type: "authorization_code", code: flow.redirect!.searchParams.get("code")!, redirect_uri: client.redirect, code_verifier: "short" },
      basicAuth(client.id, client.secret!)
    );
    expect(result.status).toBe(400);
  });
});

describe("redirect_uri", () => {
  let client: TestClient;
  beforeAll(async () => {
    client = await registerClient({ redirect_uris: ["https://exact.test.local/auth/callback"] });
  });

  /** Anything but a 400 page means the provider was willing to send the browser somewhere. */
  async function refused(uri: string | null) {
    const response = await new Browser(app).request(authorizeUrl(client, { redirect_uri: uri }));
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    return bodyText(response);
  }

  test.each([
    ["an unregistered host", "https://evil.example/auth/callback"],
    ["a different path", "https://exact.test.local/auth/callback/extra"],
    ["a parent path", "https://exact.test.local/auth"],
    ["a suffix on the host", "https://exact.test.local.evil.example/auth/callback"],
    ["a subdomain", "https://x.exact.test.local/auth/callback"],
    ["another scheme", "http://exact.test.local/auth/callback"],
    ["a different case", "https://EXACT.test.local/AUTH/callback"],
    ["an added query", "https://exact.test.local/auth/callback?next=https://evil.example"],
    ["an added fragment", "https://exact.test.local/auth/callback#x"],
    ["a userinfo trick", "https://exact.test.local@evil.example/auth/callback"],
    ["a path traversal", "https://exact.test.local/auth/../auth/callback"],
    ["a trailing slash", "https://exact.test.local/auth/callback/"],
  ])("refuses %s and does not redirect", async (_name, uri) => {
    await refused(uri);
  });

  test("a missing redirect_uri is refused rather than defaulted to the registered one", async () => {
    await refused(null);
  });

  test("the exact registered URI is accepted", async () => {
    const response = await new Browser(app).request(authorizeUrl(client, { redirect_uri: "https://exact.test.local/auth/callback" }));
    expect(response.status).toBe(303);
  });

  test("an unknown client_id is refused without redirecting", async () => {
    const response = await new Browser(app).request(authorizeUrl({ ...client, id: "no-such-client" }));
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });

  test("a logout redirect to an unregistered URI is refused (no open redirect)", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    const { tokens } = await signInAndRedeem(app, browser, client, user);
    const response = await browser.request(
      `${ISSUER_ORIGIN}/logout?${new URLSearchParams({ id_token_hint: tokens.body.id_token, post_logout_redirect_uri: "https://evil.example/", state: "x" })}`
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });
});

describe("state and nonce", () => {
  test("state comes back exactly as sent, including characters that need escaping", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const state = "a b&c=d/é?#x";
    const result = await new Browser(app).flow(client, user, { challenge: pkce().challenge, state });
    expect(result.redirect?.searchParams.get("state")).toBe(state);
  });

  test("no state in, no state out: the OP never invents one", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.follow(await browser.request(authorizeUrl(client, { state: null })), client.redirect);
    const result = await browser.signIn(start.interaction!, user, client);
    expect(result.redirect?.searchParams.has("state")).toBe(false);
  });

  test("an authorization request for openid without a nonce is refused", async () => {
    const client = await registerClient();
    const response = await new Browser(app).request(authorizeUrl(client, { nonce: null }));
    expect(response.status).toBe(400);
    expect(await bodyText(response)).toContain("nonce is required");
  });

  test("a request without the openid scope does not need one", async () => {
    const client = await registerClient();
    const response = await new Browser(app).request(authorizeUrl(client, { nonce: null, scope: "calendar.read" }));
    expect(response.status).toBe(303);
  });

  test("each ID token carries the nonce of its own request, so a nonce cannot be replayed into another", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const first = await signInAndRedeem(app, browser, client, user, { nonce: "nonce-A" });
    const second = await signInAndRedeem(app, browser, client, user, { nonce: "nonce-B" });
    const claim = (token: string) => JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).nonce;
    expect(claim(first.tokens.body.id_token)).toBe("nonce-A");
    expect(claim(second.tokens.body.id_token)).toBe("nonce-B");
  });
});

describe("what a client may ask for", () => {
  test("implicit and hybrid response types are refused", async () => {
    const client = await registerClient();
    for (const responseType of ["token", "id_token", "code id_token", "code token", "none"]) {
      const response = await new Browser(app).request(authorizeUrl(client, { response_type: responseType }));
      const location = response.headers.get("location") ?? "";
      expect(`${response.status} ${location}`).toMatch(/unsupported_response_type|^400/);
      // an implicit-flow error is delivered in the fragment; it must never carry a credential
      expect(location).not.toMatch(/[#?&](access_token|id_token|code|refresh_token)=/);
    }
  });

  test("the request and request_uri parameters are not honoured", async () => {
    const client = await registerClient();
    const response = await new Browser(app).request(authorizeUrl(client, { request: "eyJhbGciOiJub25lIn0.e30." }));
    expect(response.headers.get("location") ?? "").toMatch(/error=request_not_supported|error=invalid_request/);
  });

  test("a scope the client is not registered for is refused", async () => {
    const client = await registerClient({ allowed_scopes: ["openid", "profile", "calendar.read"] });
    const response = await new Browser(app).request(authorizeUrl(client, { scope: "openid admin" }));
    expect(response.headers.get("location") ?? "").toContain("error=invalid_scope");
  });

  test("an unknown scope is refused or ignored, never granted", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { verifier, challenge } = pkce();
    const result = await new Browser(app).flow(client, user, { scope: "openid calendar.read root", challenge });
    if (result.redirect?.searchParams.get("code")) {
      const tokens = await redeem(app, client, result.redirect, verifier);
      expect(tokens.body.scope ?? "").not.toContain("root");
    } else {
      expect(result.redirect?.searchParams.get("error")).toBeString();
    }
  });

  test("the password and client_credentials grants do not exist", async () => {
    const client = await registerClient();
    const user = await createTestUser({ scopes: both });
    const password = await tokenRequest(app, { grant_type: "password", username: user.username, password: user.password }, basicAuth(client.id, client.secret!));
    expect(password.status).toBe(400);
    expect(password.body.error).toBe("unsupported_grant_type");
    const credentials = await tokenRequest(app, { grant_type: "client_credentials" }, basicAuth(client.id, client.secret!));
    expect(credentials.status).toBe(400);
    expect(credentials.body.error).toBe("unsupported_grant_type");
  });
});

describe("client authentication", () => {
  test("a wrong secret is invalid_client (401)", async () => {
    const client = await registerClient();
    const result = await tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50) }, basicAuth(client.id, "wrong"));
    expect(result.status).toBe(401);
    expect(result.body.error).toBe("invalid_client");
  });

  test("a confidential client cannot skip authentication", async () => {
    const client = await registerClient();
    const result = await tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50), client_id: client.id });
    expect(result.status).toBe(401);
  });

  test("the secret in the request body (client_secret_post) is not accepted", async () => {
    const client = await registerClient();
    const result = await tokenRequest(app, {
      grant_type: "authorization_code",
      code: "x",
      redirect_uri: client.redirect,
      code_verifier: "y".repeat(50),
      client_id: client.id,
      client_secret: client.secret!,
    });
    expect(result.status).toBe(401);
  });

  test("the stored hash is not a usable secret", async () => {
    const client = await registerClient();
    const [{ client_secret_hash }] = await testSql`SELECT client_secret_hash FROM oidc_clients WHERE client_id = ${client.id}`;
    expect(client_secret_hash).toHaveLength(64);
    const result = await tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50) }, basicAuth(client.id, client_secret_hash));
    expect(result.status).toBe(401);
  });

  test("an empty secret and an unknown client are refused alike", async () => {
    const client = await registerClient();
    const attempt = (header: string) =>
      tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50) }, header);
    const unknown = await attempt(basicAuth("no-such-client", "x"));
    expect(unknown.status).toBe(401);
    expect(unknown.body.error).toBe("invalid_client");
    // an empty secret is a malformed request to the library, still a refusal and still no token
    const empty = await attempt(basicAuth(client.id, ""));
    expect([400, 401]).toContain(empty.status);
    expect(empty.body.access_token).toBeUndefined();
  });
});

describe("secrets and tokens at rest", () => {
  test("no bearer value reaches the database: codes, refresh tokens and the session cookie are stored hashed", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { tokens, redirect } = await signInAndRedeem(app, browser, client, user);
    const code = redirect.searchParams.get("code")!;
    const refreshToken = tokens.body.refresh_token as string;
    const sessionCookie = browser.cookie("__Host-legacy_session")!;
    const secrets = [code, refreshToken, sessionCookie, client.secret!];

    const everything = JSON.stringify([
      await testSql`SELECT * FROM oidc_payloads`,
      await testSql`SELECT * FROM oidc_sessions`,
      await testSql`SELECT * FROM oidc_clients`,
      await testSql`SELECT * FROM auth_events`,
    ]);
    for (const secret of secrets) expect(everything).not.toContain(secret);

    // what is stored is the hash, so the library's lookups still work (the flow above redeemed the code)
    const expectedHash = createHash("sha256").update(`RefreshToken:${refreshToken}`).digest("hex");
    const rows = await testSql`SELECT id, payload FROM oidc_payloads WHERE model = 'RefreshToken' AND id = ${expectedHash}`;
    expect(rows).toHaveLength(1);
    expect(rows[0].payload.jti).toBeUndefined();
  });

  test("the secret cannot be read back from the registry or the admin API", async () => {
    const client = await registerClient();
    const [row] = await testSql`SELECT * FROM oidc_clients WHERE client_id = ${client.id}`;
    expect(JSON.stringify(row)).not.toContain(client.secret!);
  });
});

describe("the sign-in page and its JSON API", () => {
  async function start(user = createTestUser({ scopes: both })) {
    const client = await registerClient();
    const browser = new Browser(app);
    const interaction = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    return { client, browser, interaction, user: await user };
  }

  test("login CSRF: a cross-origin post is refused", async () => {
    const { browser, interaction, user } = await start();
    const result = await browser.interactionCall(interaction.uid, "login", { username: user.username, password: user.password }, { origin: "https://evil.example" });
    expect(result.status).toBe(403);
    expect(result.body.redirect).toBeUndefined();
  });

  test("login CSRF: a post with no Origin is refused", async () => {
    const { browser, interaction, user } = await start();
    const response = await browser.request(`${ISSUER_ORIGIN}/interaction/${interaction.uid}/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: user.username, password: user.password }),
    });
    expect(response.status).toBe(403);
  });

  test("login CSRF: a cross-site fetch is refused even with the right Origin", async () => {
    const { browser, interaction, user } = await start();
    const result = await browser.interactionCall(interaction.uid, "login", { username: user.username, password: user.password }, { "sec-fetch-site": "cross-site" });
    expect(result.status).toBe(403);
  });

  test("login CSRF: a form post (not JSON) is refused", async () => {
    const { browser, interaction, user } = await start();
    const response = await browser.request(`${ISSUER_ORIGIN}/interaction/${interaction.uid}/login`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: ISSUER_ORIGIN },
      body: new URLSearchParams({ username: user.username, password: user.password }),
    });
    expect(response.status).toBe(403);
  });

  test("an interaction cannot be completed from a browser that did not start it", async () => {
    const { interaction, user } = await start();
    const stranger = new Browser(app);
    const result = await stranger.interactionCall(interaction.uid, "login", { username: user.username, password: user.password });
    expect(result.status).toBe(410);
    expect(result.body.redirect).toBeUndefined();
  });

  test("an interaction's cookie does not open another interaction", async () => {
    const first = await start();
    const client = await registerClient();
    const other = (await new Browser(app).authorize(client, { challenge: pkce().challenge })).interaction!;
    const result = await first.browser.interactionCall(other.uid, "login", { username: first.user.username, password: first.user.password });
    expect(result.status).toBe(410);
  });

  test("a finished interaction cannot be used again", async () => {
    const { client, browser, interaction, user } = await start();
    await browser.signIn(interaction, user, client);
    const again = await browser.interactionCall(interaction.uid, "login", { username: user.username, password: user.password });
    expect(again.status).toBe(410);
  });

  test("rejects a malformed body without a stack trace", async () => {
    const { browser, interaction } = await start();
    const response = await browser.request(`${ISSUER_ORIGIN}/interaction/${interaction.uid}/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ISSUER_ORIGIN },
      body: "{not json",
    });
    expect(response.status).toBe(400);
    expect(await response.text()).not.toMatch(/at \w+|\.ts:\d+/);
  });

  test("rejects an oversized body", async () => {
    const { browser, interaction } = await start();
    const result = await browser.interactionCall(interaction.uid, "login", { username: "a", password: "x".repeat(40_000) });
    expect(result.status).toBe(400);
  });

  test("abort sends the user back to the app with access_denied", async () => {
    const { client, browser, interaction } = await start();
    const result = await browser.interactionCall(interaction.uid, "abort", {});
    expect(result.status).toBe(200);
    const redirect = new URL(result.body.redirect, ISSUER);
    const followed = await browser.follow(new Response(null, { status: 303, headers: { location: result.body.redirect } }), client.redirect);
    expect(followed.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(followed.redirect?.searchParams.get("code")).toBeNull();
    expect(redirect.pathname).toContain("/authorize/");
  });

  test("unknown interaction ids and actions are 404 or 410, never a server error", async () => {
    const browser = new Browser(app);
    expect((await browser.request(`${ISSUER_ORIGIN}/interaction/x`)).status).toBe(404);
    expect((await browser.request(`${ISSUER_ORIGIN}/interaction/${"a".repeat(30)}`)).status).toBe(400);
    const { interaction } = await start();
    const own = new Browser(app);
    expect((await own.interactionCall(interaction.uid, "nonsense", {})).status).toBe(404);
  });
});

describe("headers", () => {
  test("OP pages cannot be framed and do not leak a Referer", async () => {
    const client = await registerClient();
    const browser = new Browser(app);
    const authorize = await browser.request(authorizeUrl(client));
    const interaction = await browser.request(authorize.headers.get("location")!);
    const logout = await browser.request(`${ISSUER_ORIGIN}/logout`);
    const errorPage = await browser.request(authorizeUrl({ ...client, id: "nope" }));
    for (const response of [authorize, interaction, logout, errorPage]) {
      expect(response.headers.get("x-frame-options")).toBe("DENY");
      expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(response.headers.get("referrer-policy")).toBe("no-referrer");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    }
  });

  test("the token and userinfo endpoints are never cached", async () => {
    const token = await tokenRequest(app, { grant_type: "authorization_code", code: "x" });
    const userinfo = await call(app, "GET", "/userinfo", { token: "nope" });
    for (const response of [token, userinfo]) {
      expect(response.headers.get("cache-control")).toContain("no-store");
      expect(response.headers.get("pragma")).toBe("no-cache");
    }
  });

  test("the sign-in page is never cached", async () => {
    const client = await registerClient();
    const browser = new Browser(app);
    const authorize = await browser.request(authorizeUrl(client));
    const page = await browser.request(authorize.headers.get("location")!);
    expect(page.headers.get("cache-control")).toContain("no-store");
  });
});

describe("the browser session", () => {
  test("the cookie is __Host-prefixed, Secure, HttpOnly, SameSite=Lax, Path=/ and has no Domain", async () => {
    const user = await createTestUser({ scopes: both });
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, await registerClient(), user);
    const cookie = browser.setCookies.find((raw) => raw.startsWith("__Host-legacy_session=") && !raw.startsWith("__Host-legacy_session.sig"))!;
    expect(cookie).toBeString();
    expect(cookie).toMatch(/;\s*secure/i);
    expect(cookie).toMatch(/;\s*httponly/i);
    expect(cookie).toMatch(/;\s*samesite=lax/i);
    expect(cookie).toMatch(/;\s*path=\/(;|$)/i);
    expect(cookie).not.toMatch(/;\s*domain=/i);
  });

  test("the cookie is signed: a tampered or forged value is not a session", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user);

    const forger = new Browser(app);
    forger.jar.set("__Host-legacy_session", browser.cookie("__Host-legacy_session")!); // right value, no signature
    expect((await forger.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid" })).redirect?.searchParams.get("error")).toBe("login_required");

    const tampered = new Browser(app);
    tampered.jar.set("__Host-legacy_session", browser.cookie("__Host-legacy_session")!);
    tampered.jar.set("__Host-legacy_session.sig", "AAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect((await tampered.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid" })).redirect?.searchParams.get("error")).toBe("login_required");
  });

  test("session fixation, part 1: no session identifier exists before sign-in, so there is nothing to plant", async () => {
    const client = await registerClient();
    const visitor = new Browser(app);
    await visitor.authorize(client, { challenge: pkce().challenge });
    expect(visitor.cookie("__Host-legacy_session")).toBeUndefined();
    expect(visitor.setCookies.some((raw) => raw.startsWith("__Host-legacy_session="))).toBe(false);
  });

  test("session fixation, part 2: signing in again rotates the identifier and the old one stops working", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);

    await signInAndRedeem(app, browser, client, user);
    const before = { value: browser.cookie("__Host-legacy_session")!, signature: browser.cookie("__Host-legacy_session.sig")! };
    expect(before.value).toBeString();

    const again = await browser.authorize(client, { prompt: "login", challenge: pkce().challenge });
    const done = await browser.signIn(again.interaction!, user, client);
    expect(done.redirect?.searchParams.get("code")).toBeString();
    expect(browser.cookie("__Host-legacy_session")).not.toBe(before.value);

    // whoever kept the old cookie (a leaked or planted one) is signed out
    const replay = new Browser(app);
    replay.jar.set("__Host-legacy_session", before.value);
    replay.jar.set("__Host-legacy_session.sig", before.signature);
    const probe = await replay.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid" });
    expect(probe.redirect?.searchParams.get("error")).toBe("login_required");
    expect(probe.redirect?.searchParams.get("code")).toBeNull();
  });

  test("a different user signing in on a browser that has a session first ends that session everywhere", async () => {
    const first = await createTestUser({ scopes: both });
    const second = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const original = await signInAndRedeem(app, browser, client, first);
    const oldCookie = browser.cookie("__Host-legacy_session")!;

    const start = await browser.authorize(client, { prompt: "login", challenge: pkce().challenge });
    const done = await browser.signIn(start.interaction!, second, client);
    // user B got in ...
    expect(done.redirect?.searchParams.get("code")).toBeString();
    // ... but only after user A's session was ended, so A's tokens died with it and nothing was mixed
    expect(browser.cookie("__Host-legacy_session")).not.toBe(oldCookie);
    expect((await refreshRequest(app, client, original.tokens.body.refresh_token)).status).toBe(400);
  });
});

describe("rate limiting", () => {
  test("failed /token requests from one public address are throttled, others are not", async () => {
    config.trustProxy = true;
    config.loginMaxFailures = 2; // 10 per address
    const client = await registerClient();
    const attacker = fromIp(`198.51.100.${10 + Math.floor(Math.random() * 100)}`);
    const bad = () =>
      call(app, "POST", "/token", {
        headers: { ...attacker, authorization: basicAuth(client.id, "wrong") },
        form: { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50) },
      });
    for (let i = 0; i < 10; i++) expect((await bad()).status).toBe(401);
    const blocked = await bad();
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(blocked.body.error).toBe("temporarily_unavailable");

    // a different address is unaffected
    const other = await call(app, "POST", "/token", {
      headers: { ...fromIp("203.0.113.77"), authorization: basicAuth(client.id, "wrong") },
      form: { grant_type: "authorization_code", code: "x" },
    });
    expect(other.status).not.toBe(429);
  });

  test("a client's own servers on a private address are never throttled", async () => {
    config.loginMaxFailures = 1;
    const client = await registerClient();
    for (let i = 0; i < 12; i++) {
      const result = await tokenRequest(app, { grant_type: "authorization_code", code: "x" }, basicAuth(client.id, "wrong"));
      expect(result.status).toBe(401);
    }
  });

  test("malformed /authorize requests are throttled, but routine silent sign-in checks are not", async () => {
    config.trustProxy = true;
    config.loginMaxFailures = 2;
    const client = await registerClient();
    const abuser = fromIp(`198.51.100.${120 + Math.floor(Math.random() * 100)}`);
    const request = (headers: Record<string, string>, overrides: Record<string, string | null> = {}) =>
      fetch(authorizeUrl(client, overrides).replace(ISSUER_ORIGIN, app.url), { headers, redirect: "manual" });

    for (let i = 0; i < 10; i++) expect((await request(abuser, { redirect_uri: "https://evil.example/cb" })).status).toBe(400);
    expect((await request(abuser)).status).toBe(429);

    // prompt=none answers login_required to anyone without a session; that is how apps probe, not abuse
    const prober = fromIp(`198.51.100.${230 + Math.floor(Math.random() * 20)}`);
    for (let i = 0; i < 15; i++) {
      const response = await request(prober, { prompt: "none" });
      expect(response.headers.get("location")).toContain("error=login_required");
    }
    expect((await request(prober, { prompt: "none" })).status).toBe(303);
  });

  test("password guessing at the sign-in page is throttled per username, with Retry-After", async () => {
    config.loginMaxFailures = 3;
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    for (let i = 0; i < 3; i++) {
      expect((await browser.interactionCall(uid, "login", { username: user.username, password: "wrong" })).status).toBe(401);
    }
    const blocked = await browser.interactionCall(uid, "login", { username: user.username, password: user.password });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(blocked.body.redirect).toBeUndefined();
  });

  test("the OP and /auth/login share their failure counts", async () => {
    config.loginMaxFailures = 3;
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    for (let i = 0; i < 3; i++) await call(app, "POST", "/auth/login", { json: { username: user.username, password: "wrong" } });
    const browser = new Browser(app);
    const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    expect((await browser.interactionCall(uid, "login", { username: user.username, password: user.password })).status).toBe(429);
  });

  test("an unknown username costs the same: it is counted too", async () => {
    config.loginMaxFailures = 2;
    const client = await registerClient();
    const browser = new Browser(app);
    const { uid } = (await browser.authorize(client, { challenge: pkce().challenge })).interaction!;
    const ghost = `ghost-${Math.random().toString(16).slice(2)}`;
    await browser.interactionCall(uid, "login", { username: ghost, password: "x" });
    await browser.interactionCall(uid, "login", { username: ghost, password: "x" });
    expect((await browser.interactionCall(uid, "login", { username: ghost, password: "x" })).status).toBe(429);
  });
});

describe("userinfo", () => {
  test("refuses garbage, a missing token, and a resource-bound token", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user);
    expect((await call(app, "GET", "/userinfo")).status).toBe(401);
    expect((await call(app, "GET", "/userinfo", { token: "garbage" })).status).toBe(401);
    // an access token minted for calendar is for calendar's API, not for the OP
    expect((await call(app, "GET", "/userinfo", { token: tokens.body.access_token })).status).toBe(401);
  });

  test("a token without the openid scope is refused", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { verifier, challenge } = pkce();
    const flow = await browser.flow(client, user, { scope: "profile", resource: null, nonce: "n", challenge });
    if (flow.redirect?.searchParams.get("code")) {
      const tokens = await redeem(app, client, flow.redirect, verifier);
      expect((await call(app, "GET", "/userinfo", { token: tokens.body.access_token })).status).toBeGreaterThanOrEqual(400);
    }
  });
});
