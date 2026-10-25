import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { ClientValidationError, ensureDefaultClients, generateClientSecret, hashClientSecret, redirectUriAllowed, secretMatchesHash, validateClientFields } from "../src/oidc/clients.ts";
import { call, createTestUser, loginOk, startApp, testSql, type TestApp } from "./helpers.ts";
import { Browser, ISSUER_ORIGIN, basicAuth, pkce, refreshRequest, registerClient, signInAndRedeem, tokenRequest, useStubFrontend } from "./oidc-helpers.ts";

let app: TestApp;
let adminToken: string;
let restoreFrontend: () => void;
const original = { internal: config.oidcAllowInternalBackchannel };

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
  config.oidcAllowInternalBackchannel = original.internal;
});

const both = { calendar: true, tracker: true };
let counter = 0;
const newId = () => `adm-${Date.now().toString(36)}-${counter++}`;

const base = (overrides: Record<string, unknown> = {}) => ({
  client_id: newId(),
  name: "Test app",
  is_public: false,
  redirect_uris: ["https://app.example.test/auth/callback"],
  post_logout_redirect_uris: ["https://app.example.test/"],
  allowed_scopes: ["openid", "profile", "calendar.read", "calendar.write", "offline_access"],
  ...overrides,
});

const create = (body: Record<string, unknown>) => call(app, "POST", "/admin/oidc/clients", { token: adminToken, json: body });
const get = (id: string) => call(app, "GET", `/admin/oidc/clients/${id}`, { token: adminToken });

describe("authorization", () => {
  test("only an admin may read or change the registry", async () => {
    const plain = (await loginOk(app, await createTestUser())).access_token;
    for (const [method, path, body] of [
      ["GET", "/admin/oidc/clients", undefined],
      ["POST", "/admin/oidc/clients", base()],
      ["GET", "/admin/oidc/clients/calendar-web", undefined],
      ["PATCH", "/admin/oidc/clients/calendar-web", { name: "x" }],
      ["POST", "/admin/oidc/clients/calendar-web/rotate-secret", {}],
      ["POST", "/admin/oidc/clients/calendar-web/disable", {}],
      ["POST", "/admin/oidc/clients/calendar-web/enable", {}],
    ] as const) {
      expect((await call(app, method, path, { json: body })).status).toBe(401);
      expect((await call(app, method, path, { token: plain, json: body })).status).toBe(403);
    }
  });
});

describe("creating clients", () => {
  test("a confidential client gets a secret, shown once", async () => {
    const body = base();
    const created = await create(body);
    expect(created.status).toBe(201);
    expect(created.headers.get("cache-control")).toContain("no-store");
    expect(created.body.client_secret).toBeString();
    expect(created.body.client_secret.length).toBeGreaterThanOrEqual(43); // 256 bits, base64url
    expect(created.body.client).toMatchObject({ client_id: body.client_id, is_public: false, disabled: false, has_secret: true });

    const read = await get(body.client_id);
    expect(JSON.stringify(read.body)).not.toContain(created.body.client_secret);
    expect(read.body.client_secret).toBeUndefined();
    expect(read.body.client_secret_hash).toBeUndefined();
  });

  test("only a hash of the secret is stored, and it is what the client authenticates against", async () => {
    const created = await create(base());
    const [row] = await testSql`SELECT client_secret_hash FROM oidc_clients WHERE client_id = ${created.body.client.client_id}`;
    expect(row.client_secret_hash).toBe(hashClientSecret(created.body.client_secret));
    expect(row.client_secret_hash).not.toBe(created.body.client_secret);
  });

  test("a public client has no secret", async () => {
    const created = await create(base({ is_public: true, redirect_uris: ["com.example.app:/cb"], post_logout_redirect_uris: [] }));
    expect(created.status).toBe(201);
    expect(created.body.client_secret).toBeUndefined();
    expect(created.body.client.has_secret).toBe(false);
  });

  test("can be created disabled", async () => {
    const created = await create(base({ disabled: true }));
    expect(created.body.client.disabled).toBe(true);
  });

  test("a duplicate id is a 409 and changes nothing", async () => {
    const body = base();
    const first = await create(body);
    const again = await create({ ...body, name: "Changed" });
    expect(again.status).toBe(409);
    const read = await get(body.client_id);
    expect(read.body.name).toBe("Test app");
    const [row] = await testSql`SELECT client_secret_hash FROM oidc_clients WHERE client_id = ${body.client_id}`;
    expect(row.client_secret_hash).toBe(hashClientSecret(first.body.client_secret));
  });

  test("lists clients without any secret material", async () => {
    await create(base());
    const list = await call(app, "GET", "/admin/oidc/clients", { token: adminToken });
    expect(list.status).toBe(200);
    expect(list.body.items.length).toBeGreaterThan(0);
    expect(JSON.stringify(list.body)).not.toMatch(/secret_hash|previous_secret_hash|"client_secret"/);
  });

  test("answers 404 for an unknown client, whatever the verb", async () => {
    for (const [method, path] of [
      ["GET", "/admin/oidc/clients/nope-nope"],
      ["PATCH", "/admin/oidc/clients/nope-nope"],
      ["POST", "/admin/oidc/clients/nope-nope/rotate-secret"],
      ["POST", "/admin/oidc/clients/nope-nope/disable"],
      ["POST", "/admin/oidc/clients/nope-nope/enable"],
    ] as const) {
      expect((await call(app, method, path, { token: adminToken, ...(method === "GET" ? {} : { json: { name: "x" } }) })).status).toBe(404);
    }
  });
});

describe("validation", () => {
  const refuses = async (overrides: Record<string, unknown>, expected: RegExp) => {
    const result = await create(base(overrides));
    expect(result.status).toBe(400);
    expect(result.body.error).toMatch(expected);
  };

  test.each([
    ["too short", "a"],
    ["upper case", "Calendar"],
    ["a space", "a b"],
    ["a slash", "a/b"],
    ["a leading dash", "-abc"],
    ["too long", "a".repeat(64)],
  ])("refuses a client_id that is %s", async (_name, id) => {
    await refuses({ client_id: id }, /client_id/);
  });

  test("refuses a missing name, a non-boolean is_public and a missing client_id", async () => {
    await refuses({ name: "" }, /name/);
    await refuses({ is_public: "yes" }, /is_public/);
    const noId = base();
    delete (noId as any).client_id;
    expect((await create(noId)).status).toBe(400);
  });

  test.each([
    ["a wildcard", "https://*.example.test/cb", /wildcard/],
    ["a fragment", "https://app.example.test/cb#x", /fragment/],
    ["a relative URI", "/cb", /absolute/],
    ["no scheme", "app.example.test/cb", /absolute|custom scheme/],
    ["javascript:", "javascript:alert(1)", /not allowed/],
    ["data:", "data:text/html,x", /not allowed/],
    ["file:", "file:///etc/passwd", /not allowed/],
    ["plain http off localhost", "http://app.example.test/cb", /only allowed for localhost/],
    ["credentials", "https://user:pass@app.example.test/cb", /credentials/],
    ["a custom scheme on a confidential client", "com.example.app:/cb", /custom scheme/],
    ["an empty string", "", /non-empty/],
    ["a number", 7, /non-empty/],
  ])("refuses a redirect URI with %s", async (_name, uri, expected) => {
    await refuses({ redirect_uris: [uri] }, expected);
  });

  test("allows https, http on localhost, and custom schemes on public clients", async () => {
    expect((await create(base({ redirect_uris: ["https://app.example.test/cb", "http://localhost:3000/cb", "http://127.0.0.1:3000/cb", "http://[::1]:3000/cb"] }))).status).toBe(201);
    expect((await create(base({ is_public: true, redirect_uris: ["com.example.app:/oauth2redirect"], post_logout_redirect_uris: [] }))).status).toBe(201);
  });

  test("refuses no redirect URIs, more than ten, and repeats", async () => {
    await refuses({ redirect_uris: [] }, /at least 1/);
    await refuses({ redirect_uris: Array.from({ length: 11 }, (_, i) => `https://app${i}.example.test/cb`) }, /at most 10/);
    await refuses({ redirect_uris: ["https://a.example.test/cb", "https://a.example.test/cb"] }, /repeat/);
    await refuses({ redirect_uris: "https://a.example.test/cb" }, /array/);
  });

  test("applies the same rules to post-logout URIs", async () => {
    await refuses({ post_logout_redirect_uris: ["http://app.example.test/"] }, /post_logout_redirect_uris/);
    await refuses({ post_logout_redirect_uris: ["https://app.example.test/#x"] }, /fragment/);
  });

  test("refuses unknown scopes, a missing openid, and repeats", async () => {
    await refuses({ allowed_scopes: ["openid", "root"] }, /unknown scope/);
    await refuses({ allowed_scopes: ["profile"] }, /include openid/);
    await refuses({ allowed_scopes: [] }, /non-empty/);
    await refuses({ allowed_scopes: ["openid", "openid"] }, /repeat/);
  });

  test("a public client can be given a back-channel endpoint: its own server receives it", async () => {
    const created = await create(base({ is_public: true, redirect_uris: ["com.example.app:/cb"], post_logout_redirect_uris: [], backchannel_logout_uri: "https://app.example.test/bc" }));
    expect(created.status).toBe(201);
    expect(created.body.client.backchannel_logout_uri).toBe("https://app.example.test/bc");
  });

  test("the primary resource and the defaults must be apps the client is registered for", async () => {
    await refuses({ primary_resource: "urn:legacy:tracker" }, /primary_resource/);
    await refuses({ primary_resource: "calendar" }, /primary_resource/);
    await refuses({ default_resources: ["urn:legacy:tracker"] }, /default_resources/);
    await refuses({ default_resources: ["urn:legacy:calendar", "urn:legacy:calendar"] }, /default_resources/);
    const created = await create(base({ primary_resource: "urn:legacy:calendar", default_resources: ["urn:legacy:calendar"] }));
    expect(created.status).toBe(201);
    expect(created.body.client).toMatchObject({ primary_resource: "urn:legacy:calendar", default_resources: ["urn:legacy:calendar"] });
  });

  test("the primary resource and the defaults can be changed, and cleared", async () => {
    const id = newId();
    await create(base({ client_id: id, allowed_scopes: ["openid", "calendar.read", "tracker.read"] }));
    const set = await call(app, "PATCH", `/admin/oidc/clients/${id}`, { token: adminToken, json: { primary_resource: "urn:legacy:tracker", default_resources: ["urn:legacy:tracker", "urn:legacy:calendar"] } });
    expect(set.body).toMatchObject({ primary_resource: "urn:legacy:tracker", default_resources: ["urn:legacy:tracker", "urn:legacy:calendar"] });
    const cleared = await call(app, "PATCH", `/admin/oidc/clients/${id}`, { token: adminToken, json: { primary_resource: null, default_resources: [] } });
    expect(cleared.body).toMatchObject({ primary_resource: null, default_resources: [] });
  });

  test("in production settings a back-channel endpoint may not point at the local network", async () => {
    config.oidcAllowInternalBackchannel = false;
    for (const target of ["http://localhost:3000/bc", "http://127.0.0.1/bc", "https://10.0.0.5/bc", "https://169.254.169.254/latest", "https://db.internal/bc", "https://printer.local/bc", "https://[::1]/bc"]) {
      await refuses({ backchannel_logout_uri: target }, /backchannel_logout_uri/);
    }
    expect((await create(base({ backchannel_logout_uri: "https://app.example.test/auth/backchannel-logout" }))).status).toBe(201);
  });

  test("outside production a local back-channel endpoint is fine, for development", async () => {
    config.oidcAllowInternalBackchannel = true;
    expect((await create(base({ backchannel_logout_uri: "http://localhost:3000/bc" }))).status).toBe(201);
  });

  test("rejects a body that is not a JSON object", async () => {
    const response = await fetch(`${app.url}/admin/oidc/clients`, { method: "POST", headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" }, body: "[1,2]" });
    expect(response.status).toBe(400);
  });
});

describe("updating clients", () => {
  test("changes only the fields given, and the OP uses them at once", async () => {
    const body = base({ redirect_uris: ["https://old.example.test/cb"] });
    const created = await create(body);
    const secret = created.body.client_secret as string;
    const user = await createTestUser({ scopes: both });

    const updated = await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token: adminToken, json: { redirect_uris: ["https://new.example.test/cb"] } });
    expect(updated.status).toBe(200);
    expect(updated.body).toMatchObject({ name: "Test app", redirect_uris: ["https://new.example.test/cb"] });

    const client = { id: body.client_id, secret, redirect: "https://new.example.test/cb", logoutRedirect: null };
    const accepted = await signInAndRedeem(app, new Browser(app), client, user);
    expect(accepted.tokens.status).toBe(200);

    const old = await new Browser(app).request(`${ISSUER_ORIGIN}/authorize?${new URLSearchParams({ client_id: body.client_id, redirect_uri: "https://old.example.test/cb", response_type: "code", scope: "openid", nonce: "n", code_challenge: pkce().challenge, code_challenge_method: "S256" })}`);
    expect(old.status).toBe(400);
  });

  test("is validated like creation, against what is already there", async () => {
    const body = base();
    await create(body);
    const bad = await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token: adminToken, json: { redirect_uris: ["http://app.example.test/cb"] } });
    expect(bad.status).toBe(400);
    const stillThere = await get(body.client_id);
    expect(stillThere.body.redirect_uris).toEqual(["https://app.example.test/auth/callback"]);
  });

  test("cannot turn a public client into a confidential one or back", async () => {
    const body = base({ is_public: true, redirect_uris: ["com.example.pub:/cb"], post_logout_redirect_uris: [] });
    await create(body);
    const result = await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token: adminToken, json: { is_public: false } });
    expect(result.status).toBe(400);
    expect(result.body.error).toContain("is_public cannot be changed");
  });

  test("refuses fields it does not know, so a typo is not silently ignored", async () => {
    const body = base();
    await create(body);
    const result = await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token: adminToken, json: { client_secret: "x", disabled_at: null } });
    expect(result.status).toBe(400);
    expect(result.body.error).toContain("client_secret");
  });

  test("restricting scopes takes effect for new sign-ins", async () => {
    const body = base();
    const created = await create(body);
    await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token: adminToken, json: { allowed_scopes: ["openid", "calendar.read"] } });
    const client = { id: body.client_id, secret: created.body.client_secret, redirect: body.redirect_uris[0], logoutRedirect: null };
    const user = await createTestUser({ scopes: both });
    const { tokens } = await signInAndRedeem(app, new Browser(app), client, user, { scope: "openid calendar.read" });
    expect(JSON.parse(Buffer.from(tokens.body.access_token.split(".")[1], "base64url").toString()).scope).toBe("calendar.read");
  });
});

describe("rotating a secret", () => {
  const redeemWith = async (client: { id: string; redirect: string }, secret: string) =>
    tokenRequest(app, { grant_type: "authorization_code", code: "x", redirect_uri: client.redirect, code_verifier: "y".repeat(50) }, basicAuth(client.id, secret));

  /** 400 means the secret was accepted and the bogus code was then refused; 401 means the secret was. */
  const accepted = (result: { status: number }) => result.status === 400;

  async function newClient() {
    const body = base();
    const created = await create(body);
    return { body, id: body.client_id as string, redirect: body.redirect_uris[0], secret: created.body.client_secret as string };
  }

  test("issues a new secret that works, and the old one keeps working for the grace period", async () => {
    const client = await newClient();
    const rotated = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: {} });
    expect(rotated.status).toBe(200);
    expect(rotated.body.client_secret).toBeString();
    expect(rotated.body.client_secret).not.toBe(client.secret);
    expect(rotated.headers.get("cache-control")).toContain("no-store");
    expect(rotated.body.client.previous_secret_expires_at).toBeString();

    expect(accepted(await redeemWith(client, rotated.body.client_secret))).toBe(true);
    expect(accepted(await redeemWith(client, client.secret))).toBe(true);
    expect((await redeemWith(client, "something else")).status).toBe(401);
  });

  test("the old secret stops working when the grace period ends", async () => {
    const client = await newClient();
    const rotated = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: {} });
    await testSql`UPDATE oidc_clients SET previous_secret_expires_at = now() - interval '1 second' WHERE client_id = ${client.id}`;
    expect((await redeemWith(client, client.secret)).status).toBe(401);
    expect(accepted(await redeemWith(client, rotated.body.client_secret))).toBe(true);
  });

  test("grace_seconds: 0 revokes the old secret at once, for a leaked one", async () => {
    const client = await newClient();
    const rotated = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: { grace_seconds: 0 } });
    expect(rotated.body.client.previous_secret_expires_at).toBeNull();
    expect((await redeemWith(client, client.secret)).status).toBe(401);
    expect(accepted(await redeemWith(client, rotated.body.client_secret))).toBe(true);
  });

  test("a second rotation replaces the previous secret: only the last two ever work", async () => {
    const client = await newClient();
    const second = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: {} });
    const third = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: {} });
    expect((await redeemWith(client, client.secret)).status).toBe(401); // the original is two rotations back
    expect(accepted(await redeemWith(client, second.body.client_secret))).toBe(true);
    expect(accepted(await redeemWith(client, third.body.client_secret))).toBe(true);
  });

  test("rotating signs nobody out: refresh tokens belong to the client, not its secret", async () => {
    const client = await newClient();
    const user = await createTestUser({ scopes: both });
    const signed = await signInAndRedeem(app, new Browser(app), { id: client.id, secret: client.secret, redirect: client.redirect, logoutRedirect: null }, user);
    const rotated = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: { grace_seconds: 0 } });
    const viaNew = await refreshRequest(app, { id: client.id, secret: rotated.body.client_secret, redirect: client.redirect, logoutRedirect: null }, signed.tokens.body.refresh_token);
    expect(viaNew.status).toBe(200);
  });

  test("refuses a public client, a bad grace period, and an unknown client", async () => {
    const pub = base({ is_public: true, redirect_uris: ["com.example.pub2:/cb"], post_logout_redirect_uris: [] });
    await create(pub);
    expect((await call(app, "POST", `/admin/oidc/clients/${pub.client_id}/rotate-secret`, { token: adminToken, json: {} })).status).toBe(400);
    const client = await newClient();
    for (const grace of [-1, "1d", 31 * 86400, null, Number.NaN]) {
      expect((await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: { grace_seconds: grace } })).status).toBe(400);
    }
  });

  test("uses the configured grace period by default", async () => {
    const client = await newClient();
    const rotated = await call(app, "POST", `/admin/oidc/clients/${client.id}/rotate-secret`, { token: adminToken, json: {} });
    const expires = new Date(rotated.body.client.previous_secret_expires_at).getTime();
    expect(Math.abs(expires - (Date.now() + config.oidcSecretRotationGraceSeconds * 1000))).toBeLessThan(5000);
  });
});

describe("disabling a client", () => {
  async function liveClient() {
    const body = base();
    const created = await create(body);
    const user = await createTestUser({ scopes: both });
    const client = { id: body.client_id as string, secret: created.body.client_secret as string, redirect: body.redirect_uris[0], logoutRedirect: null };
    const signed = await signInAndRedeem(app, new Browser(app), client, user);
    return { client, user, signed };
  }

  test("refuses new sign-ins, token requests and refreshes at once", async () => {
    const { client, signed } = await liveClient();
    const disabled = await call(app, "POST", `/admin/oidc/clients/${client.id}/disable`, { token: adminToken, json: {} });
    expect(disabled.status).toBe(200);
    expect(disabled.body.disabled).toBe(true);

    const authorize = await new Browser(app).request(`${ISSUER_ORIGIN}/authorize?${new URLSearchParams({ client_id: client.id, redirect_uri: client.redirect, response_type: "code", scope: "openid", nonce: "n", code_challenge: pkce().challenge, code_challenge_method: "S256" })}`);
    expect(authorize.status).toBe(400);
    expect(authorize.headers.get("location")).toBeNull();
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(401);
    expect((await tokenRequest(app, { grant_type: "authorization_code", code: "x" }, basicAuth(client.id, client.secret))).status).toBe(401);
  });

  test("enabling brings it back, tokens included", async () => {
    const { client, signed } = await liveClient();
    await call(app, "POST", `/admin/oidc/clients/${client.id}/disable`, { token: adminToken, json: {} });
    const enabled = await call(app, "POST", `/admin/oidc/clients/${client.id}/enable`, { token: adminToken, json: {} });
    expect(enabled.body.disabled).toBe(false);
    expect((await refreshRequest(app, client, signed.tokens.body.refresh_token)).status).toBe(200);
  });

  test("disabling twice is harmless and keeps the first timestamp", async () => {
    const { client } = await liveClient();
    const first = await call(app, "POST", `/admin/oidc/clients/${client.id}/disable`, { token: adminToken, json: {} });
    const [{ disabled_at: firstAt }] = await testSql`SELECT disabled_at FROM oidc_clients WHERE client_id = ${client.id}`;
    await call(app, "POST", `/admin/oidc/clients/${client.id}/disable`, { token: adminToken, json: {} });
    const [{ disabled_at: secondAt }] = await testSql`SELECT disabled_at FROM oidc_clients WHERE client_id = ${client.id}`;
    expect(first.status).toBe(200);
    expect(new Date(secondAt).getTime()).toBe(new Date(firstAt).getTime());
  });
});

describe("the seeded clients", () => {
  const seeded = ["calendar-web", "calendar-spa", "tracker-spa", "tracker-mobile", "auth-console"];

  test("exist, disabled, so deploying changes nothing for users", async () => {
    for (const id of seeded) {
      const client = await get(id);
      expect(client.status).toBe(200);
      expect(client.body.disabled).toBe(true);
    }
  });

  test("have the redirect URIs and scopes the issue lists", async () => {
    expect((await get("calendar-web")).body).toMatchObject({
      is_public: false,
      redirect_uris: ["https://calendar.legacy-group.tech/auth/callback"],
      allowed_scopes: ["openid", "profile", "calendar.read", "calendar.write", "offline_access"],
    });
    expect((await get("calendar-spa")).body).toMatchObject({
      is_public: true,
      redirect_uris: ["https://legacy-calendar.pages.dev/callback", "https://calendar.legacy-group.tech/callback", "http://localhost:5173/callback"],
      allowed_scopes: ["openid", "profile", "calendar.read", "calendar.write", "offline_access"],
    });
    // the tracker's two clients share the calendar read scope, a main app and the defaults (legacy-auth#8)
    const trackerScopes = ["openid", "profile", "tracker.read", "tracker.write", "calendar.read", "offline_access"];
    const trackerResources = { primary_resource: "urn:legacy:tracker", default_resources: ["urn:legacy:tracker", "urn:legacy:calendar"] };
    expect((await get("tracker-spa")).body).toMatchObject({
      is_public: true,
      redirect_uris: ["https://tracker.legacy-group.tech/callback", "https://legacytracker.pages.dev/callback", "http://localhost:5173/callback"],
      post_logout_redirect_uris: ["https://tracker.legacy-group.tech/", "https://legacytracker.pages.dev/", "http://localhost:5173/"],
      backchannel_logout_uri: "https://tracker.legacy-group.tech/auth/backchannel-logout",
      allowed_scopes: trackerScopes,
      ...trackerResources,
    });
    expect((await get("tracker-mobile")).body).toMatchObject({
      is_public: true,
      redirect_uris: ["com.legacy.legacytracker:/oauth2redirect"],
      post_logout_redirect_uris: ["com.legacy.legacytracker:/logout"],
      backchannel_logout_uri: "https://tracker.legacy-group.tech/auth/backchannel-logout",
      allowed_scopes: trackerScopes,
      ...trackerResources,
    });
    expect((await get("auth-console")).body).toMatchObject({
      is_public: false,
      redirect_uris: [`${ISSUER_ORIGIN}/auth/callback`],
      allowed_scopes: ["openid", "profile", "admin", "offline_access"],
    });
  });

  test("confidential ones have no secret until an admin rotates one in", async () => {
    for (const id of ["calendar-web", "auth-console"]) expect((await get(id)).body.has_secret).toBe(false);
    for (const id of ["tracker-spa", "tracker-mobile"]) expect((await get(id)).body.has_secret).toBe(false);
  });

  test("cannot be enabled without a secret, and can afterwards", async () => {
    const refused = await call(app, "POST", "/admin/oidc/clients/calendar-web/enable", { token: adminToken, json: {} });
    expect(refused.status).toBe(409);
    expect(refused.body.error).toContain("rotate");

    const rotated = await call(app, "POST", "/admin/oidc/clients/calendar-web/rotate-secret", { token: adminToken, json: {} });
    expect(rotated.status).toBe(200);
    expect((await call(app, "POST", "/admin/oidc/clients/calendar-web/enable", { token: adminToken, json: {} })).status).toBe(200);
    // leave things as found for the rest of the run
    await call(app, "POST", "/admin/oidc/clients/calendar-web/disable", { token: adminToken, json: {} });
    await testSql`UPDATE oidc_clients SET client_secret_hash = NULL, previous_secret_hash = NULL, previous_secret_expires_at = NULL WHERE client_id = 'calendar-web'`;
  });

  test("a confidential client that was never given a secret is unknown to the provider, not open to anyone", async () => {
    await testSql`UPDATE oidc_clients SET disabled_at = NULL WHERE client_id = 'auth-console'`;
    try {
      const response = await new Browser(app).request(`${ISSUER_ORIGIN}/authorize?${new URLSearchParams({ client_id: "auth-console", redirect_uri: `${ISSUER_ORIGIN}/auth/callback`, response_type: "code", scope: "openid", nonce: "n", code_challenge: pkce().challenge, code_challenge_method: "S256" })}`);
      expect(response.status).toBe(400);
      const token = await tokenRequest(app, { grant_type: "authorization_code", code: "x" }, basicAuth("auth-console", ""));
      expect([400, 401]).toContain(token.status);
    } finally {
      await testSql`UPDATE oidc_clients SET disabled_at = now() WHERE client_id = 'auth-console'`;
    }
  });

  test("seeding again adds nothing and never overwrites an edited client", async () => {
    await call(app, "PATCH", "/admin/oidc/clients/tracker-spa", { token: adminToken, json: { name: "Edited by an admin" } });
    try {
      expect(await ensureDefaultClients()).toEqual([]);
      expect((await get("tracker-spa")).body.name).toBe("Edited by an admin");
    } finally {
      await call(app, "PATCH", "/admin/oidc/clients/tracker-spa", { token: adminToken, json: { name: "Legacy Tracker (web)" } });
    }
  });
});

describe("audit trail", () => {
  test("records who changed the registry, without secrets", async () => {
    const admin = await createTestUser({ role: "admin" });
    const token = (await loginOk(app, admin)).access_token;
    const body = base();
    const created = await call(app, "POST", "/admin/oidc/clients", { token, json: body });
    await call(app, "PATCH", `/admin/oidc/clients/${body.client_id}`, { token, json: { name: "Renamed" } });
    const rotated = await call(app, "POST", `/admin/oidc/clients/${body.client_id}/rotate-secret`, { token, json: {} });
    await call(app, "POST", `/admin/oidc/clients/${body.client_id}/disable`, { token, json: {} });
    await call(app, "POST", `/admin/oidc/clients/${body.client_id}/enable`, { token, json: {} });

    let rows: any[] = [];
    for (let attempt = 0; attempt < 50 && rows.length < 5; attempt++) {
      rows = await testSql`SELECT event, actor_id, detail FROM auth_events WHERE actor_id = ${admin.id} AND event LIKE 'admin_oidc_client_%' ORDER BY id`;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    expect(rows.map((row) => row.event)).toEqual([
      "admin_oidc_client_create",
      "admin_oidc_client_update",
      "admin_oidc_client_rotate_secret",
      "admin_oidc_client_disable",
      "admin_oidc_client_enable",
    ]);
    expect(rows.every((row) => row.actor_id === admin.id && String(row.detail).startsWith(body.client_id))).toBe(true);
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(created.body.client_secret);
    expect(dump).not.toContain(rotated.body.client_secret);
  });
});

describe("secrets and validation, as plain functions", () => {
  test("generated secrets are long, random and distinct", () => {
    const secrets = new Set(Array.from({ length: 50 }, generateClientSecret));
    expect(secrets.size).toBe(50);
    for (const secret of secrets) expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test("a hash matches its own secret and nothing else", () => {
    const secret = generateClientSecret();
    const hash = hashClientSecret(secret);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(secretMatchesHash(secret, hash)).toBe(true);
    expect(secretMatchesHash(`${secret}x`, hash)).toBe(false);
    expect(secretMatchesHash(hash, hash)).toBe(false);
    expect(secretMatchesHash("", hash)).toBe(false);
    expect(secretMatchesHash(secret, null)).toBe(false);
    expect(secretMatchesHash(secret, undefined)).toBe(false);
    expect(secretMatchesHash(secret, "short")).toBe(false);
  });

  test("validateClientFields merges a partial update over the current fields", () => {
    const current = validateClientFields(base() as any);
    expect(validateClientFields({ name: "New" }, current).redirect_uris).toEqual(current.redirect_uris);
    expect(() => validateClientFields({ name: "" }, current)).toThrow(ClientValidationError);
  });
});

describe("redirect URI matching", () => {
  const registered = ["https://legacy-calendar.pages.dev/callback", "http://localhost:5173/cb", "com.example.app:/cb"];

  test("accepts a registered URI exactly", () => {
    for (const uri of registered) expect(redirectUriAllowed(uri, registered)).toBe(true);
  });

  test("accepts the same path and query on a subdomain, at any depth", () => {
    expect(redirectUriAllowed("https://feature-x.legacy-calendar.pages.dev/callback", registered)).toBe(true);
    expect(redirectUriAllowed("https://a.b.legacy-calendar.pages.dev/callback", registered)).toBe(true);
    expect(redirectUriAllowed("http://preview.localhost:5173/cb", registered)).toBe(true);
  });

  test("does not accept a parent, a lookalike, or a different path, query, port or scheme", () => {
    for (const uri of [
      "https://pages.dev/callback",
      "https://evillegacy-calendar.pages.dev/callback",
      "https://legacy-calendar.pages.dev.evil.example/callback",
      "https://feature-x.legacy-calendar.pages.dev/callback/extra",
      "https://feature-x.legacy-calendar.pages.dev/callback?next=evil",
      "https://feature-x.legacy-calendar.pages.dev:8443/callback",
      "http://feature-x.legacy-calendar.pages.dev/callback",
      "https://feature-x.legacy-calendar.pages.dev/auth/../callback",
      "https://feature-x.legacy-calendar.pages.dev/callback#x",
      "https://user:pass@feature-x.legacy-calendar.pages.dev/callback",
    ]) {
      expect(redirectUriAllowed(uri, registered)).toBe(false);
    }
  });

  test("never treats an IP address as a domain with subdomains", () => {
    expect(redirectUriAllowed("https://1.2.3.4/cb", ["https://1.2.3.4/cb"])).toBe(true);
    expect(redirectUriAllowed("https://x.1.2.3.4/cb", ["https://1.2.3.4/cb"])).toBe(false);
    expect(redirectUriAllowed("https://[::1]/cb", ["https://[::1]/cb"])).toBe(true);
    expect(redirectUriAllowed("https://x.[::1]/cb", ["https://[::1]/cb"])).toBe(false);
  });

  test("has no subdomains on a custom scheme, and tolerates a missing list", () => {
    expect(redirectUriAllowed("com.example.app:/cb", registered)).toBe(true);
    expect(redirectUriAllowed("something.com.example.app:/cb", registered)).toBe(false);
    expect(redirectUriAllowed("https://example.test/cb", undefined)).toBe(false);
  });
});
