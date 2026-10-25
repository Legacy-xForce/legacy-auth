import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { isPrivateAddress, resetThrottleWindows } from "../src/throttle.ts";
import { call, createTestUser, fromIp, login, startApp, type TestApp } from "./helpers.ts";

let app: TestApp;
const original = { max: config.loginMaxFailures, proxy: config.trustProxy };

beforeAll(() => {
  app = startApp();
});
afterAll(() => {
  app.stop();
  resetThrottleWindows();
});
beforeEach(() => {
  resetThrottleWindows();
});
afterEach(() => {
  config.loginMaxFailures = original.max;
  config.trustProxy = original.proxy;
});

describe("failed-login throttling", () => {
  test("answers 429 with Retry-After once a username has used its failures", async () => {
    config.loginMaxFailures = 3;
    const user = await createTestUser();
    for (let i = 0; i < 3; i++) {
      expect((await login(app, { ...user, password: "wrong" })).status).toBe(401);
    }
    const blocked = await login(app, { ...user, password: "wrong" });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(Number(blocked.headers.get("retry-after"))).toBeLessThanOrEqual(config.loginFailureWindowSeconds);
  });

  test("blocks even the correct password while throttled", async () => {
    config.loginMaxFailures = 2;
    const user = await createTestUser();
    await login(app, { ...user, password: "wrong" });
    await login(app, { ...user, password: "wrong" });
    expect((await login(app, user)).status).toBe(429);
  });

  test("one user's failures do not block another user", async () => {
    config.loginMaxFailures = 2;
    const victim = await createTestUser();
    const other = await createTestUser();
    await login(app, { ...victim, password: "wrong" });
    await login(app, { ...victim, password: "wrong" });
    expect((await login(app, victim)).status).toBe(429);
    expect((await login(app, other)).status).toBe(200);
  });

  test("a successful sign-in clears the username's count", async () => {
    config.loginMaxFailures = 3;
    const user = await createTestUser();
    await login(app, { ...user, password: "wrong" });
    await login(app, { ...user, password: "wrong" });
    expect((await login(app, user)).status).toBe(200);
    // two more failures are fine again: the count restarted
    await login(app, { ...user, password: "wrong" });
    await login(app, { ...user, password: "wrong" });
    expect((await login(app, user)).status).toBe(200);
  });

  test("counts unknown usernames too, so enumeration cannot probe freely", async () => {
    config.loginMaxFailures = 2;
    const ghost = { id: "x", username: `ghost${Date.now()}${Math.random().toString(16).slice(2)}`, password: "wrong" };
    await login(app, ghost);
    await login(app, ghost);
    expect((await login(app, ghost)).status).toBe(429);
  });

  test("per-IP limit is five times the per-username limit and applies across usernames", async () => {
    config.loginMaxFailures = 2; // IP limit: 10
    config.trustProxy = true;
    const ip = `198.51.100.${1 + Math.floor(Math.random() * 200)}`;
    const attacker = fromIp(ip);
    for (let i = 0; i < 10; i++) {
      const result = await call(app, "POST", "/auth/login", {
        headers: attacker,
        json: { username: `spray${i}-${Math.random().toString(16).slice(2)}`, password: "wrong" },
      });
      expect(result.status).toBe(401);
    }
    const blocked = await call(app, "POST", "/auth/login", { headers: attacker, json: { username: "fresh-name", password: "wrong" } });
    expect(blocked.status).toBe(429);

    // a different client address is unaffected
    const bystander = await createTestUser();
    const ok = await call(app, "POST", "/auth/login", { headers: fromIp("203.0.113.9"), json: { username: bystander.username, password: bystander.password } });
    expect(ok.status).toBe(200);
  });

  test("ignores X-Forwarded-For unless TRUST_PROXY is on", async () => {
    config.loginMaxFailures = 1; // IP limit: 5
    config.trustProxy = false;
    const spoofed = fromIp("198.51.100.77");
    for (let i = 0; i < 8; i++) {
      await call(app, "POST", "/auth/login", { headers: spoofed, json: { username: `s${i}-${Math.random().toString(16).slice(2)}`, password: "wrong" } });
    }
    const user = await createTestUser();
    const result = await call(app, "POST", "/auth/login", { headers: spoofed, json: { username: user.username, password: user.password } });
    expect(result.status).toBe(200);
  });

  test("change-password failures are throttled as well", async () => {
    config.loginMaxFailures = 2;
    const user = await createTestUser();
    const tokens = (await login(app, user)).body;
    const attempt = () =>
      call(app, "POST", "/auth/change-password", { token: tokens.access_token, json: { current_password: "wrong", new_password: "something-else" } });
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(429);
  });
});

describe("isPrivateAddress", () => {
  test.each([
    ["127.0.0.1", true],
    ["10.1.2.3", true],
    ["172.16.0.1", true],
    ["172.31.255.255", true],
    ["172.32.0.1", false],
    ["192.168.1.1", true],
    ["169.254.1.1", true],
    ["::1", true],
    ["fd00::1", true],
    ["fe80::1", true],
    ["::ffff:10.0.0.1", true],
    ["8.8.8.8", false],
    ["203.0.113.5", false],
    ["2001:db8::1", false],
  ])("%s -> %p", (address, expected) => {
    expect(isPrivateAddress(address)).toBe(expected);
  });
});
