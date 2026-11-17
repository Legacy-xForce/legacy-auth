import { describe, expect, test } from "bun:test";
import { config } from "../src/config.ts";
import { findUserById, insertAuthEvent, listAuthEvents, listUsersPaginated, updateUserPasswordHash, upgradeLegacyPasswordHash } from "../src/db.ts";
import { toCachedUser } from "../src/cache.ts";
import { isDeprecatedEndpoint, markDeprecated, DEPRECATED_ENDPOINTS } from "../src/lib/deprecated.ts";
import { toPublicUser } from "../src/lib/public-user.ts";
import { tokenResponse } from "../src/lib/tokens.ts";
import { checkPasswordLogin } from "../src/oidc/credentials.ts";
import { previousSecretValid } from "../src/oidc/clients.ts";
import { assertPublicTarget, internalTargetProblem } from "../src/oidc/net-safety.ts";
import { issuerOrigin, issuerUrl } from "../src/oidc/origin.ts";
import { APP_AUDIENCES, type UserRecord } from "../src/types.ts";
import { RESOURCE_SERVERS, resourceForAudience, seedScopes, SUPPORTED_SCOPES } from "../src/oidc/scopes.ts";
import { createTestUser, loginOk, startApp, testSql } from "./helpers.ts";

const record = (overrides: Partial<UserRecord> = {}): UserRecord => ({
  id: "8f14e45f-ceea-467e-bb92-42f2c1e6b6d1",
  username: "alice",
  display_name: "Alice",
  password_hash: "$argon2id$v=19$m=65536,t=2,p=1$abc$def",
  role: "user",
  active: true,
  scopes: { calendar: true, tracker: false },
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
  ...overrides,
});

describe("previousSecretValid — the one secret-rotation grace rule", () => {
  const now = new Date("2026-06-01T00:00:00.000Z").getTime();
  const future = "2026-06-02T00:00:00.000Z";
  const past = "2026-05-31T00:00:00.000Z";

  test("needs a hash", () => {
    expect(previousSecretValid(null, future, now)).toBe(false);
    expect(previousSecretValid(undefined, future, now)).toBe(false);
    expect(previousSecretValid("", future, now)).toBe(false);
    expect(previousSecretValid("hash", future, now)).toBe(true);
  });

  test("accepts the three expiry shapes the code actually carries", () => {
    expect(previousSecretValid("hash", future, now)).toBe(true); // DB string
    expect(previousSecretValid("hash", new Date(future), now)).toBe(true); // Bun's timestamptz Date
    expect(previousSecretValid("hash", new Date(future).getTime() / 1000, now)).toBe(true); // provider: Unix seconds
  });

  test("rejects expired and malformed expiries", () => {
    expect(previousSecretValid("hash", past, now)).toBe(false);
    expect(previousSecretValid("hash", new Date(past), now)).toBe(false);
    expect(previousSecretValid("hash", new Date(past).getTime() / 1000, now)).toBe(false);
    expect(previousSecretValid("hash", null, now)).toBe(false);
    expect(previousSecretValid("hash", "nonsense", now)).toBe(false);
    expect(previousSecretValid("hash", Number.NaN, now)).toBe(false);
  });

  test("an expiry exactly now is already expired", () => {
    expect(previousSecretValid("hash", new Date(now).toISOString(), now)).toBe(false);
  });
});

describe("canonical scope/resource constants", () => {
  test("seedScopes keeps the historical order, derived from IDENTITY_SCOPES", () => {
    expect(seedScopes()).toEqual(["openid", "profile", "offline_access"]);
    expect(seedScopes("calendar.read", "calendar.write")).toEqual([
      "openid", "profile", "calendar.read", "calendar.write", "offline_access",
    ]);
    expect(seedScopes("admin")).toEqual(["openid", "profile", "admin", "offline_access"]);
  });

  test("resourceForAudience agrees with RESOURCE_SERVERS for every app", () => {
    for (const app of APP_AUDIENCES) {
      const resource = resourceForAudience(app);
      expect(resource.audience).toBe(app);
      expect(resource.indicator).toBe(`urn:legacy:${app}`);
      expect(RESOURCE_SERVERS[resource.indicator]).toBe(resource);
      for (const scope of resource.scopes) expect(SUPPORTED_SCOPES).toContain(scope);
    }
  });

  test("the seeded tracker scope set is exactly the old literal", () => {
    const calendar = resourceForAudience("calendar");
    const tracker = resourceForAudience("tracker");
    expect(seedScopes(...tracker.scopes, calendar.scopes[0])).toEqual([
      "openid", "profile", "tracker.read", "tracker.write", "calendar.read", "offline_access",
    ]);
  });
});

describe("shared response shapes", () => {
  test("tokenResponse uses the configured lifetimes", () => {
    expect(tokenResponse("a", "r")).toEqual({
      access_token: "a",
      refresh_token: "r",
      expires_in: config.accessTokenTtlSeconds,
      refresh_expires_in: config.refreshTokenTtlSeconds,
    });
  });

  test("toPublicUser never leaks the password hash", () => {
    const user = record({ password_hash: "super-secret" });
    const json = JSON.stringify(toPublicUser(user));
    expect(json).not.toContain("super-secret");
    expect(Object.keys(toPublicUser(user)).sort()).toEqual([
      "active", "created_at", "display_name", "id", "role", "scopes", "updated_at", "username",
    ]);
  });

  test("toCachedUser keeps exactly the login fields", () => {
    expect(toCachedUser(record())).toEqual({
      id: record().id, username: "alice", display_name: "Alice",
      password_hash: record().password_hash, role: "user", active: true,
      scopes: { calendar: true, tracker: false },
    });
  });
});

describe("deprecation metadata", () => {
  test("one source lists exactly the retired endpoints", () => {
    expect([...DEPRECATED_ENDPOINTS].sort()).toEqual([
      "POST /auth/login", "POST /auth/passkey/login-options", "POST /auth/passkey/login-verify",
    ]);
    expect(isDeprecatedEndpoint("post", "/auth/login")).toBe(true);
    expect(isDeprecatedEndpoint("POST", "/auth/refresh")).toBe(false);
  });

  test("markDeprecated adds headers only to those endpoints", () => {
    const marked = markDeprecated(new Request("https://auth.test.local/auth/login", { method: "POST" }), new Response());
    expect(marked.headers.get("deprecation")).toBe("true");
    expect(marked.headers.get("link")).toContain(`${config.jwtIssuer}/.well-known/openid-configuration`);

    const plain = markDeprecated(new Request("https://auth.test.local/auth/refresh", { method: "POST" }), new Response());
    expect(plain.headers.has("deprecation")).toBe(false);
  });
});

describe("manual JSON object parsing (previously copy-pasted)", () => {
  test("arrays and malformed JSON get the original 400 messages", async () => {
    const app = startApp();
    try {
      const array = await fetch(`${app.url}/auth/passkey/login-options`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "[1,2]",
      });
      expect(array.status).toBe(400);
      expect((await array.json() as any).error).toBe("A JSON object body is required");

      const malformed = await fetch(`${app.url}/auth/passkey/login-options`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{",
      });
      expect(malformed.status).toBe(400);
      expect((await malformed.json() as any).error).toBe("Malformed JSON in request body");

      const empty = await fetch(`${app.url}/auth/passkey/login-options`, { method: "POST" });
      expect(empty.status).toBe(200); // an absent body is still {}
    } finally {
      app.stop();
    }
  });
});

describe("bcrypt -> Argon2 upgrade (previously untested, now shared)", () => {
  test("upgradeLegacyPasswordHash is a no-op for a current hash", async () => {
    const user = await createTestUser();
    const current = await findUserById(user.id);
    expect(await upgradeLegacyPasswordHash(current as UserRecord, user.password)).toBeNull();
  });

  test("legacy /auth/login upgrades the stored hash", async () => {
    const user = await createTestUser();
    await updateUserPasswordHash(user.id, await Bun.password.hash(user.password, { algorithm: "bcrypt", cost: 4 }));
    const app = startApp();
    try {
      expect((await loginOk(app, user)).access_token).toBeString();
    } finally {
      app.stop();
    }
    const [row] = await testSql`SELECT password_hash FROM users WHERE id = ${user.id}`;
    expect(row.password_hash.startsWith("$2")).toBe(false);
    expect(await Bun.password.verify(user.password, row.password_hash)).toBe(true);
  });

  test("the OIDC login path upgrades the same way", async () => {
    const user = await createTestUser();
    await updateUserPasswordHash(user.id, await Bun.password.hash(user.password, { algorithm: "bcrypt", cost: 4 }));
    const result = await checkPasswordLogin(user.username, user.password, null);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.user.password_hash.startsWith("$2")).toBe(false);
    expect(await Bun.password.verify(user.password, result.user.password_hash)).toBe(true);
  });
});

describe("single-round-trip pagination", () => {
  test("a page past the end reports the filtered total", async () => {
    const user = await createTestUser();
    const first = await listUsersPaginated({ search: user.username, page: 1, pageSize: 10 });
    expect(first.total).toBe(1);
    expect(first.items).toHaveLength(1);
    const beyond = await listUsersPaginated({ search: user.username, page: 1000, pageSize: 10 });
    expect(beyond.items).toEqual([]);
    expect(beyond.total).toBe(1);
  });

  test("audit events do the same", async () => {
    const user = await createTestUser();
    await insertAuthEvent({ event: "test.event", success: true, userId: user.id, username: user.username });
    const first = await listAuthEvents({ event: "test.event", username: user.username, page: 1, pageSize: 10 });
    expect(first.total).toBe(1);
    expect(first.items).toHaveLength(1);
    const beyond = await listAuthEvents({ event: "test.event", username: user.username, page: 1000, pageSize: 10 });
    expect(beyond.items).toEqual([]);
    expect(beyond.total).toBe(1);
  });
});

describe("issuer and net-safety helpers", () => {
  test("the issuer URL and origin are parsed once and agree", () => {
    expect(issuerOrigin).toBe(new URL(config.jwtIssuer).origin);
    expect(issuerUrl.host).toBe(new URL(config.jwtIssuer).host);
  });

  test("internalTargetProblem accepts an already parsed URL", () => {
    expect(internalTargetProblem(new URL("http://localhost/x"))).toContain("local or private");
    expect(internalTargetProblem(new URL("https://app.example.test/x"))).toBeNull();
  });

  test("assertPublicTarget reports an invalid URL without throwing a raw TypeError", async () => {
    await expect(assertPublicTarget("not a url")).rejects.toThrow(/not a valid URL/);
  });
});
