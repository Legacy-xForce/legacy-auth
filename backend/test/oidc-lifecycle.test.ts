import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { statSync } from "fs";
import { dirname } from "path";
import { config } from "../src/config.ts";
import { oidc } from "../src/oidc/index.ts";
import { isOidcPath } from "../src/oidc/proxy.ts";
import { call, createTestUser, login, startApp, testSql, type TestApp } from "./helpers.ts";
import { Browser, ISSUER, ISSUER_ORIGIN, pkce, registerClient, signInAndRedeem, useStubFrontend } from "./oidc-helpers.ts";

let app: TestApp;
let restoreFrontend: () => void;
const original = { enabled: config.oidcEnabled, tmpdir: process.env.TMPDIR, trustProxy: config.trustProxy };

beforeAll(() => {
  app = startApp();
  restoreFrontend = useStubFrontend();
});
afterAll(async () => {
  app.stop();
  restoreFrontend();
  // leave the shared provider running for whatever test file runs next
  config.oidcEnabled = true;
  if (original.tmpdir === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = original.tmpdir;
  if (!oidc.running) await oidc.start();
});
afterEach(() => {
  config.trustProxy = original.trustProxy;
});

const both = { calendar: true, tracker: true };

describe("which paths belong to the OP", () => {
  test.each([
    "/authorize",
    "/authorize/abc123",
    "/token",
    "/userinfo",
    "/logout",
    "/logout/confirm",
    "/logout/success",
    "/interaction/abc",
    "/interaction/abc/login",
    "/.well-known/openid-configuration",
  ])("%s is the OP's", (path) => {
    expect(isOidcPath(path)).toBe(true);
  });

  test.each([
    "/auth/login",
    "/auth/logout",
    "/auth/refresh",
    "/auth/me",
    "/auth/passkey/login-options",
    "/.well-known/jwks.json",
    "/.well-known/assetlinks.json",
    "/admin/users",
    "/admin/oidc/clients",
    "/docs",
    "/openapi.json",
    "/",
    "/users",
    "/authorizex",
    "/tokens",
    "/tokenize",
    "/userinfo2",
    "/logoutx",
    "/interactions",
  ])("%s is not", (path) => {
    expect(isOidcPath(path)).toBe(false);
  });
});

describe("switching the OP off (OIDC_ENABLED=false)", () => {
  test("nothing is started, its paths answer 404 rather than the console page, and the legacy login still works", async () => {
    config.oidcEnabled = false;
    await oidc.stop();
    try {
      expect(oidc.running).toBe(false);
      await oidc.start();
      expect(oidc.running).toBe(false);

      for (const path of ["/authorize", "/token", "/userinfo", "/logout", "/.well-known/openid-configuration", "/interaction/abcdefghijk"]) {
        const response = await call(app, "GET", path);
        expect(response.status).toBe(404);
        expect(response.headers.get("content-type")).toContain("application/json");
      }
      expect((await call(app, "POST", "/token", { form: { grant_type: "authorization_code" } })).status).toBe(404);

      const user = await createTestUser({ scopes: both });
      expect((await login(app, user)).status).toBe(200);
      expect((await call(app, "GET", "/.well-known/jwks.json")).status).toBe(200);
    } finally {
      config.oidcEnabled = true;
      await oidc.start();
    }
    expect(oidc.running).toBe(true);
  });

  test("switching it back on brings the same clients and sessions back, since they live in the database", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    await signInAndRedeem(app, browser, client, user);

    config.oidcEnabled = false;
    await oidc.stop();
    config.oidcEnabled = true;
    await oidc.start();

    const probe = await browser.authorize(client, { prompt: "none", challenge: pkce().challenge, scope: "openid profile calendar.read calendar.write" });
    expect(probe.redirect?.searchParams.get("code")).toBeString();
  });

  test("stop and start can repeat", async () => {
    for (let i = 0; i < 3; i++) {
      await oidc.stop();
      await oidc.start();
      expect(oidc.running).toBe(true);
    }
    const discovery = await call(app, "GET", "/.well-known/openid-configuration");
    expect(discovery.status).toBe(200);
  });
});

describe("when the OP cannot start", () => {
  test("its paths answer 503, everything else carries on, and a later start recovers", async () => {
    await oidc.stop();
    process.env.TMPDIR = "/nonexistent/directory/for/the/socket"; // the socket cannot be created
    const errors: unknown[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => errors.push(args);
    try {
      await oidc.start();
    } finally {
      console.error = originalError;
    }
    try {
      expect(oidc.running).toBe(false);
      expect(JSON.stringify(errors)).toContain("failed to start");

      for (const path of ["/authorize", "/token", "/.well-known/openid-configuration"]) {
        const response = await call(app, "GET", path);
        expect(response.status).toBe(503);
        expect(response.body.error).toBe("temporarily_unavailable");
      }

      // the legacy login and the key set are untouched by the OP's failure
      const user = await createTestUser({ scopes: both });
      expect((await login(app, user)).status).toBe(200);
      expect((await call(app, "GET", "/.well-known/jwks.json")).status).toBe(200);
      expect((await call(app, "GET", "/openapi.json")).status).toBe(200);
    } finally {
      if (original.tmpdir === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = original.tmpdir;
    }
    await oidc.start();
    expect(oidc.running).toBe(true);
    expect((await call(app, "GET", "/.well-known/openid-configuration")).status).toBe(200);
  });

  test("account lifecycle changes do not fail while the OP is down", async () => {
    await oidc.stop();
    config.oidcEnabled = false;
    try {
      const admin = await createTestUser({ role: "admin" });
      const adminToken = ((await login(app, admin)).body as any).access_token;
      const victim = await createTestUser({ scopes: both });
      expect((await call(app, "PATCH", `/admin/users/${victim.id}`, { token: adminToken, json: { active: false } })).status).toBe(200);
      expect((await call(app, "DELETE", `/admin/users/${victim.id}`, { token: adminToken })).status).toBe(204);
    } finally {
      config.oidcEnabled = true;
      await oidc.start();
    }
  });
});

describe("the private socket", () => {
  test("is a Unix socket in a directory only the service can enter", () => {
    const socket = statSync(oidc.socketPath);
    expect(socket.isSocket()).toBe(true);
    expect(statSync(dirname(oidc.socketPath)).mode & 0o777).toBe(0o700);
  });

  test("is removed when the OP stops, so nothing is left lying around", async () => {
    const path = oidc.socketPath;
    await oidc.stop();
    expect(() => statSync(path)).toThrow();
    await oidc.start();
    expect(oidc.socketPath).not.toBe(path);
  });
});

describe("what the proxy believes about a request", () => {
  async function loginEvents(userId: string) {
    for (let attempt = 0; attempt < 50; attempt++) {
      const rows = await testSql`SELECT ip, user_agent FROM auth_events WHERE event = 'oidc.login' AND user_id = ${userId}`;
      if (rows.length > 0) return rows;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return [];
  }

  test("a client-supplied x-client-ip is overwritten, so the audit log cannot be told a false address", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const { interaction } = await browser.authorize(client, { challenge: pkce().challenge });
    const result = await browser.interactionCall(interaction!.uid, "login", { username: user.username, password: user.password }, { "x-client-ip": "6.6.6.6", "user-agent": "forged-agent/1" });
    expect(result.status).toBe(200);
    const [row] = await loginEvents(user.id);
    expect(row.ip).not.toBe("6.6.6.6");
    expect(row.user_agent).toBe("forged-agent/1"); // the user agent is what the browser says; only the address is vouched for
  });

  test("X-Forwarded-For is ignored unless TRUST_PROXY is on, and honoured only from a private peer when it is", async () => {
    const client = await registerClient();
    const record = async (headers: Record<string, string>) => {
      const user = await createTestUser({ scopes: both });
      const browser = new Browser(app);
      const { interaction } = await browser.authorize(client, { challenge: pkce().challenge });
      await browser.interactionCall(interaction!.uid, "login", { username: user.username, password: user.password }, headers);
      return (await loginEvents(user.id))[0].ip as string;
    };
    config.trustProxy = false;
    expect(await record({ "x-forwarded-for": "198.51.100.9" })).not.toBe("198.51.100.9");
    config.trustProxy = true;
    expect(await record({ "x-forwarded-for": "198.51.100.9" })).toBe("198.51.100.9");
  });

  test("a forged X-Forwarded-Proto or Host changes neither the cookie's Secure flag nor the issuer", async () => {
    const user = await createTestUser({ scopes: both });
    const client = await registerClient();
    const browser = new Browser(app);
    const spoof = { "x-forwarded-proto": "http", "x-forwarded-host": "evil.example", forwarded: "proto=http;host=evil.example" };
    const first = await browser.authorize(client, { challenge: pkce().challenge });
    const login = await browser.interactionCall(first.interaction!.uid, "login", { username: user.username, password: user.password }, spoof);
    await browser.follow(new Response(null, { status: 303, headers: { location: login.body.redirect } }), client.redirect);
    const cookie = browser.setCookies.find((raw) => raw.startsWith("__Host-legacy_session=") && !raw.startsWith("__Host-legacy_session.sig"))!;
    expect(cookie).toMatch(/;\s*secure/i);

    const discovery = await call(app, "GET", "/.well-known/openid-configuration", { headers: { ...spoof, host: "evil.example" } });
    expect(discovery.body.issuer).toBe(ISSUER);
    expect(discovery.body.token_endpoint).toBe(`${ISSUER_ORIGIN}/token`);
  });

  test("an error inside the OP is a bare JSON error, never a stack trace", async () => {
    const response = await call(app, "POST", "/token", { form: { grant_type: "authorization_code" }, headers: { authorization: "Basic !!!not-base64!!!" } });
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(response.body)).not.toMatch(/at \w+|\.(ts|js):\d+|node_modules/);
  });
});
