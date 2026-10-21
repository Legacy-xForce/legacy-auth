import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { call, createSoftwareAuthenticator, createTestUser, decode, fromIp, loginOk, startApp, testSql, verifyWithJwks, type TestApp } from "./helpers.ts";
import { Browser, ISSUER_ORIGIN, pkce, redeem, registerClient, useStubFrontend } from "./oidc-helpers.ts";

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

/** A user with a passkey (registered through the existing API), and a browser at the OP's sign-in page. */
async function withPasskey(options: { scopes?: { calendar: boolean; tracker: boolean } } = {}) {
  const user = await createTestUser({ scopes: options.scopes ?? both });
  const session = await loginOk(app, user);
  const authenticator = createSoftwareAuthenticator();
  const registration = await call(app, "POST", "/auth/passkey/register-options", { token: session.access_token });
  const registered = await call(app, "POST", "/auth/passkey/register-verify", {
    token: session.access_token,
    json: authenticator.registration(registration.body.challenge),
  });
  expect(registered.status).toBe(200);

  const client = await registerClient();
  const browser = new Browser(app);
  const verifier = pkce();
  const start = await browser.authorize(client, { challenge: verifier.challenge });
  return { user, authenticator, client, browser, uid: start.interaction!.uid, verifier: verifier.verifier };
}

const optionsFor = (browser: Browser, uid: string, body: object = {}) => browser.interactionCall(uid, "passkey/options", body);

describe("signing in with a passkey at the OP", () => {
  test("completes the flow, and the ID token says a passkey was used", async () => {
    const { user, authenticator, client, browser, uid, verifier } = await withPasskey();
    const options = await optionsFor(browser, uid, { username: user.username });
    expect(options.status).toBe(200);
    expect(options.body.allowCredentials.map((entry: any) => entry.id)).toContain(authenticator.credentialId);

    const verified = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge));
    expect(verified.status).toBe(200);
    const flow = await browser.follow(new Response(null, { status: 303, headers: { location: verified.body.redirect } }), client.redirect);
    expect(flow.redirect?.searchParams.get("code")).toBeString();

    const tokens = await redeem(app, client, flow.redirect!, verifier);
    expect(tokens.status).toBe(200);
    const idToken = verifyWithJwks(tokens.body.id_token, { audience: client.id }) as any;
    expect(idToken.sub).toBe(user.id);
    expect(idToken.amr).toEqual(["webauthn"]);
    expect(idToken.acr).toBe("urn:legacy:loa:1");
    expect(verifyWithJwks(tokens.body.access_token, { audience: "calendar" }).sub).toBe(user.id);
  });

  test("works without naming a user (a discoverable credential)", async () => {
    const { authenticator, client, browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid, {});
    expect(options.body.allowCredentials).toEqual([]);
    const verified = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge));
    expect(verified.status).toBe(200);
    const flow = await browser.follow(new Response(null, { status: 303, headers: { location: verified.body.redirect } }), client.redirect);
    expect(flow.redirect?.searchParams.get("code")).toBeString();
  });

  test("a password and a passkey are told apart by amr", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { verifier, challenge } = pkce();
    const flow = await browser.flow(client, user, { challenge });
    const tokens = await redeem(app, client, flow.redirect!, verifier);
    expect((verifyWithJwks(tokens.body.id_token) as any).amr).toEqual(["pwd"]);
  });

  test("a challenge works exactly once", async () => {
    const { authenticator, browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid);
    expect((await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge, { counter: 1 }))).status).toBe(200);
    // the browser has not followed the redirect yet, so the interaction is still open, but its challenge is spent
    const again = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge, { counter: 2 }));
    expect(again.status).toBe(401);
    expect(again.body.error).toContain("challenge");
  });

  test("a challenge cannot be replayed into another interaction", async () => {
    const { authenticator, client, browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid);
    await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge, { counter: 1 }));

    const other = new Browser(app);
    const second = (await other.authorize(client, { challenge: pkce().challenge })).interaction!;
    const replay = await other.interactionCall(second.uid, "passkey/verify", authenticator.assertion(options.body.challenge, { counter: 2 }));
    expect(replay.status).toBe(401);
    expect(replay.body.redirect).toBeUndefined();
  });

  test("a bad signature is refused and finishes nothing", async () => {
    const { authenticator, client, browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid);
    const bad = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge, { tamper: true }));
    expect(bad.status).toBe(401);
    expect(bad.body.redirect).toBeUndefined();
    // the interaction is still open, and a good attempt still works
    const retry = await optionsFor(browser, uid);
    const good = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(retry.body.challenge, { counter: 1 }));
    expect(good.status).toBe(200);
    void client;
  });

  test("an assertion without user presence is refused", async () => {
    const { authenticator, browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid);
    expect((await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge, { userPresent: false }))).status).toBe(401);
  });

  test("a replayed signature counter is refused", async () => {
    const { authenticator, browser, uid, client } = await withPasskey();
    const first = await optionsFor(browser, uid);
    await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(first.body.challenge, { counter: 7 }));
    const other = new Browser(app);
    const next = (await other.authorize(client, { challenge: pkce().challenge, prompt: "login" })).interaction!;
    const options = await optionsFor(other, next.uid);
    expect((await other.interactionCall(next.uid, "passkey/verify", authenticator.assertion(options.body.challenge, { counter: 7 }))).status).toBe(401);
  });

  test("an unknown credential is refused", async () => {
    const { browser, uid } = await withPasskey();
    const options = await optionsFor(browser, uid);
    const stranger = createSoftwareAuthenticator();
    expect((await browser.interactionCall(uid, "passkey/verify", stranger.assertion(options.body.challenge))).status).toBe(401);
  });

  test("a disabled account is refused with 403", async () => {
    const { user, authenticator, browser, uid } = await withPasskey();
    await testSql`UPDATE users SET active = false WHERE id = ${user.id}`;
    const options = await optionsFor(browser, uid);
    expect((await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge))).status).toBe(403);
  });

  test("a passkey of a user without the app's scope signs in but gets access_denied for that app", async () => {
    const { authenticator, client, browser, uid } = await withPasskey({ scopes: { calendar: false, tracker: true } });
    const options = await optionsFor(browser, uid);
    const verified = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge));
    expect(verified.status).toBe(200);
    const flow = await browser.follow(new Response(null, { status: 303, headers: { location: verified.body.redirect } }), client.redirect);
    expect(flow.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(flow.redirect?.searchParams.get("code")).toBeNull();
  });

  test("signing in at the OP issues no legacy refresh token", async () => {
    const { user, authenticator, client, browser, uid } = await withPasskey();
    const before = await testSql`SELECT count(*)::int AS n FROM refresh_tokens WHERE user_id = ${user.id}`;
    const options = await optionsFor(browser, uid);
    const verified = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge));
    await browser.follow(new Response(null, { status: 303, headers: { location: verified.body.redirect } }), client.redirect);
    const after = await testSql`SELECT count(*)::int AS n FROM refresh_tokens WHERE user_id = ${user.id}`;
    expect(after[0].n).toBe(before[0].n);
  });
});

describe("guards on the passkey calls", () => {
  test("cross-origin posts are refused, like the password form", async () => {
    const { authenticator, browser, uid } = await withPasskey();
    const options = await browser.interactionCall(uid, "passkey/options", {}, { origin: "https://evil.example" });
    expect(options.status).toBe(403);
    const real = await optionsFor(browser, uid);
    const verify = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(real.body.challenge), { origin: "https://evil.example" });
    expect(verify.status).toBe(403);
  });

  test("another browser cannot use someone's interaction", async () => {
    const { authenticator, uid, client } = await withPasskey();
    const stranger = new Browser(app);
    await stranger.authorize(client, { challenge: pkce().challenge }); // gets its own interaction cookie
    const options = await call(app, "POST", `/interaction/${uid}/passkey/options`, {
      headers: { origin: ISSUER_ORIGIN, cookie: "" },
      json: {},
    });
    expect(options.status).toBe(410);
    void authenticator;
  });

  test("a malformed assertion is a 401, not a server error", async () => {
    const { browser, uid } = await withPasskey();
    for (const body of [{}, { id: "x" }, { id: "x", response: {} }, { id: "x", response: { clientDataJSON: "!!!" } }]) {
      const result = await browser.interactionCall(uid, "passkey/verify", body);
      expect(result.status).toBe(401);
      expect(result.body.redirect).toBeUndefined();
    }
  });

  test("failures are throttled per client address", async () => {
    config.trustProxy = true;
    config.loginMaxFailures = 2; // 10 per address
    const { browser, uid } = await withPasskey();
    const ip = fromIp(`198.51.100.${1 + Math.floor(Math.random() * 200)}`);
    const stranger = createSoftwareAuthenticator();
    for (let i = 0; i < 10; i++) {
      const options = await optionsFor(browser, uid);
      expect((await browser.interactionCall(uid, "passkey/verify", stranger.assertion(options.body.challenge), ip)).status).toBe(401);
    }
    const options = await optionsFor(browser, uid);
    const blocked = await browser.interactionCall(uid, "passkey/verify", stranger.assertion(options.body.challenge), ip);
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  test("the passkey endpoints only make sense at a login prompt", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const start = await browser.authorize(client, { challenge: pkce().challenge });
    await browser.signIn(start.interaction!, user, client);
    // that interaction is over; a new one for consent is never shown to the user
    const stale = await optionsFor(browser, start.interaction!.uid);
    expect(stale.status).toBe(410);
  });

  test("the decoded token header is the same key the legacy endpoints publish", async () => {
    const { authenticator, client, browser, uid, verifier } = await withPasskey();
    const options = await optionsFor(browser, uid);
    const verified = await browser.interactionCall(uid, "passkey/verify", authenticator.assertion(options.body.challenge));
    const flow = await browser.follow(new Response(null, { status: 303, headers: { location: verified.body.redirect } }), client.redirect);
    const tokens = await redeem(app, client, flow.redirect!, verifier);
    const jwks = (await call(app, "GET", "/.well-known/jwks.json")).body;
    expect(decode(tokens.body.access_token).header.kid).toBe(jwks.keys[0].kid);
  });
});
