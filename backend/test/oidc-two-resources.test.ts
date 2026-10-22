import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createTestUser, decode, startApp, testSql, verifyWithJwks, type TestApp } from "./helpers.ts";
import { Browser, ISSUER, pkce, redeem, refreshRequest, registerClient, useStubFrontend, type TestClient } from "./oidc-helpers.ts";

// The tracker shows calendar events with the user's own token, so one sign-in has to be able to
// produce a token for the tracker and one for the calendar (legacy-auth#4). The client asks for
// both apps in the authorization request (two `resource` parameters, RFC 8707) and then names the
// app it wants a token for each time it uses the token endpoint.

let app: TestApp;
let restoreFrontend: () => void;

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(async () => {
  // refused requests record their audit events without being waited for; let the last ones land
  await new Promise((resolve) => setTimeout(resolve, 100));
  app.stop();
  restoreFrontend();
});

const TRACKER = "urn:legacy:tracker";
const CALENDAR = "urn:legacy:calendar";
const SCOPES = "openid profile tracker.read tracker.write calendar.read calendar.write offline_access";
const TRACKER_ONLY_SCOPES = ["openid", "profile", "tracker.read", "tracker.write", "offline_access"];

const both = { calendar: true, tracker: true };

const claimsOf = (token: string) => decode(token).payload as any;

/** The checks calendar and tracker apply to an access token since Phase 0, written out as they apply them. */
function acceptedBy(app: "calendar" | "tracker", token: string): boolean {
  const claims = verifyWithJwks(token, { issuer: ISSUER }) as any;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  return claims.type === "access" && audiences.includes(app) && claims.scopes?.[app] === true;
}

/** Signs `user` in at `client`, by default asking for the tracker and the calendar together. */
async function signIn(client: TestClient, user: Awaited<ReturnType<typeof createTestUser>>, options: { resource?: string | string[]; scope?: string } = {}) {
  const { verifier, challenge } = pkce();
  const result = await new Browser(app).flow(client, user, { resource: options.resource ?? [TRACKER, CALENDAR], scope: options.scope ?? SCOPES, challenge });
  return { result, verifier };
}

/** A grant for both apps, redeemed for the tracker. */
async function signInForBoth(client: TestClient, scopes = both) {
  const user = await createTestUser({ scopes });
  const { result, verifier } = await signIn(client, user);
  const tokens = await redeem(app, client, result.redirect!, verifier, TRACKER);
  expect(tokens.status).toBe(200);
  return { user, tokens };
}

const clientKinds: Record<string, () => Promise<TestClient>> = {
  "a confidential client (a web app's server)": () => registerClient(),
  "a public client (the phone app)": () => registerClient({ is_public: true, redirect_uris: ["com.legacy.test:/oauth2redirect"] }),
};

for (const [kind, register] of Object.entries(clientKinds)) {
  describe(`${kind} with one grant for the tracker and the calendar`, () => {
    test("one sign-in reaches the client with a single code", async () => {
      const client = await register();
      const { result } = await signIn(client, await createTestUser({ scopes: both }));
      expect(result.redirect?.searchParams.get("code")).toBeString();
      expect(result.redirect?.searchParams.get("error")).toBeNull();
    });

    test("one refresh token serves both apps, in either order", async () => {
      const client = await register();
      const user = await createTestUser({ scopes: both });
      const { result, verifier } = await signIn(client, user);

      // the app named when redeeming only decides what the first access token is for
      const first = await redeem(app, client, result.redirect!, verifier, TRACKER);
      expect(first.status).toBe(200);
      expect(first.body.id_token).toBeString();
      expect(claimsOf(first.body.access_token)).toMatchObject({ aud: "tracker", scope: "tracker.read tracker.write", client_id: client.id, sub: user.id });
      expect(acceptedBy("tracker", first.body.access_token)).toBe(true);
      expect(acceptedBy("calendar", first.body.access_token)).toBe(false);

      const second = await refreshRequest(app, client, first.body.refresh_token, CALENDAR);
      expect(second.status).toBe(200);
      expect(second.body.refresh_token).not.toBe(first.body.refresh_token);
      expect(decode(second.body.access_token).header).toMatchObject({ alg: "ES256", typ: "at+jwt" });
      expect(claimsOf(second.body.access_token)).toMatchObject({
        aud: "calendar",
        scope: "calendar.read calendar.write",
        client_id: client.id,
        sub: user.id,
        type: "access",
        username: user.username,
        scopes: both,
      });
      expect(acceptedBy("calendar", second.body.access_token)).toBe(true);
      expect(acceptedBy("tracker", second.body.access_token)).toBe(false);
      // still one session, so logout and the provider's bookkeeping see one `sid`
      expect(claimsOf(second.body.access_token).sid).toBe(claimsOf(first.body.access_token).sid);

      // the rotated token goes back to the tracker, and on to the calendar again
      const third = await refreshRequest(app, client, second.body.refresh_token, TRACKER);
      expect(third.status).toBe(200);
      expect(claimsOf(third.body.access_token).aud).toBe("tracker");
      const fourth = await refreshRequest(app, client, third.body.refresh_token, CALENDAR);
      expect(fourth.status).toBe(200);
      expect(claimsOf(fourth.body.access_token).aud).toBe("calendar");
    });

    test("an access token for one app is not accepted by the other", async () => {
      const client = await register();
      const { tokens } = await signInForBoth(client);
      const calendar = await refreshRequest(app, client, tokens.body.refresh_token, CALENDAR);
      expect(() => verifyWithJwks(tokens.body.access_token, { audience: "calendar" })).toThrow(/audience invalid/);
      expect(() => verifyWithJwks(calendar.body.access_token, { audience: "tracker" })).toThrow(/audience invalid/);
    });
  });
}

describe("what is refused when a sign-in asks for both apps", () => {
  test("a user without access to one of them gets no code at all", async () => {
    const client = await registerClient();
    const { result } = await signIn(client, await createTestUser({ scopes: { calendar: false, tracker: true } }));
    expect(result.redirect?.searchParams.get("error")).toBe("access_denied");
    expect(result.redirect?.searchParams.get("error_description")).toContain("no access to calendar");
    expect(result.redirect?.searchParams.get("code")).toBeNull();
  });

  test("a client registered for one app cannot ask for both", async () => {
    const client = await registerClient({ allowed_scopes: TRACKER_ONLY_SCOPES });
    const { result } = await signIn(client, await createTestUser({ scopes: both }));
    expect(result.redirect?.searchParams.get("error")).toBe("invalid_scope");
    expect(result.redirect?.searchParams.get("code")).toBeNull();
  });

  test("the same user and client can still sign in for the tracker alone", async () => {
    const client = await registerClient();
    const user = await createTestUser({ scopes: { calendar: false, tracker: true } });
    const { result, verifier } = await signIn(client, user, { resource: TRACKER, scope: TRACKER_ONLY_SCOPES.join(" ") });
    const tokens = await redeem(app, client, result.redirect!, verifier);
    expect(tokens.status).toBe(200);
    expect(claimsOf(tokens.body.access_token)).toMatchObject({ aud: "tracker", scopes: { calendar: false, tracker: true } });
  });
});

describe("the token endpoint needs to be told which app", () => {
  test("a code for two apps is not redeemed for a guessed one", async () => {
    const client = await registerClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: both }));
    const tokens = await redeem(app, client, result.redirect!, verifier);
    expect(tokens.status).toBe(400);
    expect(tokens.body.error).toBe("invalid_target");
    expect(tokens.body.access_token).toBeUndefined();
  });

  test("a grant for one app is redeemed for that app without saying so", async () => {
    const client = await registerClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: both }), { resource: TRACKER, scope: TRACKER_ONLY_SCOPES.join(" ") });
    const tokens = await redeem(app, client, result.redirect!, verifier);
    expect(tokens.status).toBe(200);
    expect(claimsOf(tokens.body.access_token).aud).toBe("tracker");
  });

  test("a code for the tracker alone cannot be redeemed for the calendar", async () => {
    const client = await registerClient();
    const { result, verifier } = await signIn(client, await createTestUser({ scopes: both }), { resource: TRACKER, scope: TRACKER_ONLY_SCOPES.join(" ") });
    const tokens = await redeem(app, client, result.redirect!, verifier, CALENDAR);
    expect(tokens.status).toBe(400);
    expect(tokens.body.error).toBe("invalid_target");
  });
});

// The library rotates a refresh token *before* it works out which app the request is for and whether
// the user may still have it, so a refresh that is refused would leave the client holding a spent
// token, and presenting that again would revoke the grant. The provider checks first instead
// (`refuseBeforeRotating` in provider.ts): a refused request leaves the token as it was.
describe("a refused refresh keeps the refresh token", () => {
  test("asking a grant for both apps for neither in particular", async () => {
    const client = await registerClient();
    const { tokens } = await signInForBoth(client);
    const refused = await refreshRequest(app, client, tokens.body.refresh_token);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");

    const again = await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
    expect(again.status).toBe(200);
    expect(claimsOf(again.body.access_token).aud).toBe("tracker");
  });

  test("asking a grant made for the tracker alone for the calendar", async () => {
    const client = await registerClient();
    const user = await createTestUser({ scopes: both });
    const { result, verifier } = await signIn(client, user, { resource: TRACKER, scope: TRACKER_ONLY_SCOPES.join(" ") });
    const tokens = await redeem(app, client, result.redirect!, verifier);

    const refused = await refreshRequest(app, client, tokens.body.refresh_token, CALENDAR);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");

    const again = await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
    expect(again.status).toBe(200);
    expect(claimsOf(again.body.access_token).aud).toBe("tracker");
  });

  test("losing the calendar scope: the tracker keeps refreshing until someone asks for a calendar token", async () => {
    const client = await registerClient();
    const { user, tokens } = await signInForBoth(client);
    await testSql`UPDATE users SET scopes = '{"calendar": false, "tracker": true}'::jsonb WHERE id = ${user.id}`;

    // the tracker token says the calendar is gone, which is what a client checks before asking for one
    const tracker = await refreshRequest(app, client, tokens.body.refresh_token, TRACKER);
    expect(tracker.status).toBe(200);
    expect(claimsOf(tracker.body.access_token).scopes).toEqual({ calendar: false, tracker: true });

    // asking anyway is refused, and takes the tracker session with it
    const refused = await refreshRequest(app, client, tracker.body.refresh_token, CALENDAR);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_grant");

    const after = await refreshRequest(app, client, tracker.body.refresh_token, TRACKER);
    expect(after.status).toBe(400);
    expect(after.body.error).toBe("invalid_grant");
  });
});
