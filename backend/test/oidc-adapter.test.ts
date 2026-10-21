import { describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "crypto";
import { PostgresAdapter } from "../src/oidc/adapter.ts";
import { requestContext } from "../src/oidc/context.ts";
import { purgeExpired, touchSession } from "../src/oidc/sessions.ts";
import { createTestUser, testSql } from "./helpers.ts";
import { registerClient } from "./oidc-helpers.ts";

const id = () => randomBytes(24).toString("base64url");
const hashed = (model: string, value: string) => createHash("sha256").update(`${model}:${value}`).digest("hex");
const now = () => Math.floor(Date.now() / 1000);

describe("payloads (grants, codes, refresh tokens, interactions)", () => {
  test("round-trips, with the bearer value restored on the way out and never stored", async () => {
    const adapter = new PostgresAdapter("RefreshToken");
    const token = id();
    await adapter.upsert(token, { jti: token, kind: "RefreshToken", accountId: "acct", grantId: "g-1", scope: "openid" }, 60);

    const found = await adapter.find(token);
    expect(found).toMatchObject({ jti: token, kind: "RefreshToken", accountId: "acct", grantId: "g-1", scope: "openid" });

    const [row] = await testSql`SELECT id, payload, grant_id FROM oidc_payloads WHERE model = 'RefreshToken' AND id = ${hashed("RefreshToken", token)}`;
    expect(row.id).toBe(hashed("RefreshToken", token));
    expect(row.payload.jti).toBeUndefined();
    expect(row.grant_id).toBe("g-1");
    expect(JSON.stringify(await testSql`SELECT * FROM oidc_payloads WHERE id = ${row.id}`)).not.toContain(token);
  });

  test("a value does not find a row of another model", async () => {
    const token = id();
    await new PostgresAdapter("AccessToken").upsert(token, { jti: token }, 60);
    expect(await new PostgresAdapter("RefreshToken").find(token)).toBeUndefined();
    expect(await new PostgresAdapter("AccessToken").find(token)).toBeDefined();
  });

  test("an expired row is not found", async () => {
    const adapter = new PostgresAdapter("AuthorizationCode");
    const code = id();
    await adapter.upsert(code, { jti: code }, 60);
    await testSql`UPDATE oidc_payloads SET expires_at = now() - interval '1 second' WHERE id = ${hashed("AuthorizationCode", code)}`;
    expect(await adapter.find(code)).toBeUndefined();
  });

  test("upserting again replaces the payload and the deadline", async () => {
    const adapter = new PostgresAdapter("Grant");
    const grant = id();
    await adapter.upsert(grant, { jti: grant, scope: "a" }, 60);
    await adapter.upsert(grant, { jti: grant, scope: "a b" }, 600);
    expect((await adapter.find(grant))!.scope).toBe("a b");
    const [{ ttl }] = await testSql`SELECT extract(epoch FROM (expires_at - now()))::float AS ttl FROM oidc_payloads WHERE id = ${hashed("Grant", grant)}`;
    expect(Number(ttl)).toBeGreaterThan(500);
  });

  test("consume marks a row used, once: the second attempt is invalid_grant", async () => {
    const adapter = new PostgresAdapter("AuthorizationCode");
    const code = id();
    await adapter.upsert(code, { jti: code }, 60);
    expect((await adapter.find(code))!.consumed).toBeUndefined();
    await adapter.consume(code);
    const consumed = (await adapter.find(code))!.consumed as number;
    expect(Math.abs(consumed - now())).toBeLessThan(5);
    await expect(adapter.consume(code)).rejects.toMatchObject({ error: "invalid_grant" });
  });

  test("two concurrent consumes: exactly one succeeds", async () => {
    const adapter = new PostgresAdapter("RefreshToken");
    const token = id();
    await adapter.upsert(token, { jti: token }, 60);
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => adapter.consume(token)));
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  });

  test("consuming something that does not exist fails rather than pretending", async () => {
    await expect(new PostgresAdapter("RefreshToken").consume(id())).rejects.toMatchObject({ error: "invalid_grant" });
  });

  test("an upsert after consume keeps the row consumed", async () => {
    const adapter = new PostgresAdapter("RefreshToken");
    const token = id();
    await adapter.upsert(token, { jti: token }, 60);
    await adapter.consume(token);
    await adapter.upsert(token, { jti: token, extra: true }, 60);
    expect((await adapter.find(token))!.consumed).toBeNumber();
  });

  test("destroy removes one row; revokeByGrantId removes every row of a grant and no others", async () => {
    const grant = `grant-${id()}`;
    const tokens = [id(), id(), id()];
    const mine = new PostgresAdapter("RefreshToken");
    const theirs = new PostgresAdapter("AccessToken");
    for (const token of tokens) await mine.upsert(token, { jti: token, grantId: grant }, 60);
    const unrelated = id();
    await mine.upsert(unrelated, { jti: unrelated, grantId: "someone-else" }, 60);
    const otherModel = id();
    await theirs.upsert(otherModel, { jti: otherModel, grantId: grant }, 60);

    await mine.destroy(tokens[0]);
    expect(await mine.find(tokens[0])).toBeUndefined();
    expect(await mine.find(tokens[1])).toBeDefined();

    await mine.revokeByGrantId(grant);
    expect(await mine.find(tokens[1])).toBeUndefined();
    expect(await mine.find(tokens[2])).toBeUndefined();
    expect(await mine.find(unrelated)).toBeDefined();
    expect(await theirs.find(otherModel)).toBeDefined(); // another model's rows are its own business
  });

  test("an interaction is found by its uid, and by its cookie value", async () => {
    const adapter = new PostgresAdapter("Interaction");
    const value = id();
    const uid = id();
    await adapter.upsert(value, { jti: value, uid, params: { client_id: "x" } }, 60);
    expect((await adapter.findByUid(uid))!.params).toEqual({ client_id: "x" });
    expect((await adapter.find(value))!.uid).toBe(uid);
    expect(await adapter.findByUid("nope")).toBeUndefined();
  });

  test("the device-code lookup is off", async () => {
    expect(await new PostgresAdapter("DeviceCode").findByUserCode("ABCD-EFGH")).toBeUndefined();
  });
});

describe("sessions", () => {
  const session = async (accountId?: string) => {
    const cookie = id();
    const uid = id();
    return { cookie, uid, payload: { jti: cookie, uid, ...(accountId ? { accountId, loginTs: now(), amr: ["pwd"] } : {}) } };
  };

  test("are found by cookie value and by uid, with the cookie value restored and never stored", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await adapter.upsert(cookie, payload, 3600);

    expect((await adapter.find(cookie))!.jti).toBe(cookie);
    expect((await adapter.find(cookie))!.accountId).toBe(user.id);
    expect((await adapter.findByUid(uid))!.uid).toBe(uid);

    const [row] = await testSql`SELECT * FROM oidc_sessions WHERE id = ${uid}`;
    expect(row.token_hash).toBe(hashed("Session", cookie));
    expect(row.user_id).toBe(user.id);
    expect(row.amr).toEqual(["pwd"]);
    expect(row.auth_time).toBeTruthy();
    expect(JSON.stringify(row)).not.toContain(cookie);
  });

  test("records the address and user agent of the request that made them", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await requestContext.run({ ip: "203.0.113.9", userAgent: "adapter-test/1" }, () => adapter.upsert(cookie, payload, 3600));
    const [row] = await testSql`SELECT ip, user_agent FROM oidc_sessions WHERE id = ${uid}`;
    expect(row).toMatchObject({ ip: "203.0.113.9", user_agent: "adapter-test/1" });
  });

  test("an anonymous session has no user", async () => {
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session();
    await adapter.upsert(cookie, payload, 3600);
    const [row] = await testSql`SELECT user_id, amr, auth_time FROM oidc_sessions WHERE id = ${uid}`;
    expect(row).toMatchObject({ user_id: null, amr: null, auth_time: null });
  });

  test("destroying one revokes it: it is no longer found, but the row stays for the record", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await adapter.upsert(cookie, payload, 3600);
    await adapter.destroy(cookie);
    expect(await adapter.find(cookie)).toBeUndefined();
    expect(await adapter.findByUid(uid)).toBeUndefined();
    const [row] = await testSql`SELECT revoked_at FROM oidc_sessions WHERE id = ${uid}`;
    expect(row.revoked_at).not.toBeNull();
  });

  test("a stale save of a revoked cookie cannot bring the session back", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await adapter.upsert(cookie, payload, 3600);
    await adapter.destroy(cookie); // logout
    await adapter.upsert(cookie, payload, 3600); // a request that was already in flight saves it again
    expect(await adapter.find(cookie)).toBeUndefined();
    const [row] = await testSql`SELECT revoked_at FROM oidc_sessions WHERE id = ${uid}`;
    expect(row.revoked_at).not.toBeNull();
  });

  test("rotating the cookie value keeps one row, moves it to the new value and makes the old one worthless", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie: oldCookie, uid, payload } = await session(user.id);
    await adapter.upsert(oldCookie, payload, 3600);

    // what the library does at sign-in: destroy the old identifier, save under a new one, same uid
    const newCookie = id();
    await adapter.destroy(oldCookie);
    await adapter.upsert(newCookie, { ...payload, jti: newCookie }, 3600);

    expect(await adapter.find(oldCookie)).toBeUndefined();
    expect((await adapter.find(newCookie))!.uid).toBe(uid);
    expect(await testSql`SELECT 1 FROM oidc_sessions WHERE id = ${uid}`).toHaveLength(1);
    const [row] = await testSql`SELECT revoked_at FROM oidc_sessions WHERE id = ${uid}`;
    expect(row.revoked_at).toBeNull();
  });

  test("an expired session is not found", async () => {
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session();
    await adapter.upsert(cookie, payload, 3600);
    await testSql`UPDATE oidc_sessions SET expires_at = now() - interval '1 second' WHERE id = ${uid}`;
    expect(await adapter.find(cookie)).toBeUndefined();
  });

  test("deleting the user deletes their sessions", async () => {
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await adapter.upsert(cookie, payload, 3600);
    await testSql`DELETE FROM users WHERE id = ${user.id}`;
    expect(await testSql`SELECT 1 FROM oidc_sessions WHERE id = ${uid}`).toHaveLength(0);
  });

  test("touching a session that does not exist, or is revoked, does nothing and does not fail", async () => {
    await touchSession(undefined);
    await touchSession("no-such-session");
    const user = await createTestUser();
    const adapter = new PostgresAdapter("Session");
    const { cookie, uid, payload } = await session(user.id);
    await adapter.upsert(cookie, payload, 60);
    await adapter.destroy(cookie);
    await touchSession(uid);
    const [row] = await testSql`SELECT revoked_at, extract(epoch FROM (expires_at - now()))::float AS ttl FROM oidc_sessions WHERE id = ${uid}`;
    expect(row.revoked_at).not.toBeNull();
    expect(Number(row.ttl)).toBeLessThan(120);
  });
});

describe("clients", () => {
  test("are read from the registry, and cannot be written through the library", async () => {
    const client = await registerClient();
    const adapter = new PostgresAdapter("Client");
    expect(await adapter.find(client.id)).toMatchObject({ client_id: client.id, token_endpoint_auth_method: "client_secret_basic", id_token_signed_response_alg: "ES256" });
    expect(await adapter.find("no-such-client")).toBeUndefined();
    await expect(adapter.upsert(client.id, { client_id: client.id }, 60)).rejects.toThrow(/admin API/);
  });

  test("an id that could not be a client id is not even looked up", async () => {
    const adapter = new PostgresAdapter("Client");
    for (const value of ["", "A", "x".repeat(100), "a b", "'; DROP TABLE oidc_clients; --", "../../etc/passwd"]) {
      expect(await adapter.find(value)).toBeUndefined();
    }
    expect((await testSql`SELECT count(*)::int AS n FROM oidc_clients`)[0].n).toBeGreaterThan(0);
  });

  test("a disabled client, and a confidential client with no secret, are not found", async () => {
    const disabled = await registerClient({ disabled: true });
    expect(await new PostgresAdapter("Client").find(disabled.id)).toBeUndefined();
    const keyless = await registerClient();
    await testSql`UPDATE oidc_clients SET client_secret_hash = NULL WHERE client_id = ${keyless.id}`;
    expect(await new PostgresAdapter("Client").find(keyless.id)).toBeUndefined();
  });

  test("only a client redirected to a custom scheme is native; a web app, localhost included, is not", async () => {
    const web = await registerClient();
    const local = await registerClient({ redirect_uris: ["http://localhost:4100/callback"], post_logout_redirect_uris: ["http://localhost:4100/"] });
    const native = await registerClient({ is_public: true, redirect_uris: ["com.example.adapter:/cb"] });
    const type = async (client: { id: string }) => (await new PostgresAdapter("Client").find(client.id))!.application_type;
    expect(await type(web)).toBe("web");
    expect(await type(local)).toBe("web");
    expect(await type(native)).toBe("native");
  });
});

describe("purging", () => {
  test("removes what has expired and keeps what has not", async () => {
    const live = new PostgresAdapter("RefreshToken");
    const [old, fresh] = [id(), id()];
    await live.upsert(old, { jti: old }, 60);
    await live.upsert(fresh, { jti: fresh }, 60);
    await testSql`UPDATE oidc_payloads SET expires_at = now() - interval '1 minute' WHERE id = ${hashed("RefreshToken", old)}`;
    await purgeExpired();
    expect(await testSql`SELECT 1 FROM oidc_payloads WHERE id = ${hashed("RefreshToken", old)}`).toHaveLength(0);
    expect(await live.find(fresh)).toBeDefined();
  });

  test("keeps a session for a week after it ends, then removes it", async () => {
    const adapter = new PostgresAdapter("Session");
    const make = async (sql: (uid: string) => Promise<unknown>) => {
      const cookie = id();
      const uid = id();
      await adapter.upsert(cookie, { jti: cookie, uid }, 3600);
      await sql(uid);
      return uid;
    };
    const recentlyExpired = await make((uid) => testSql`UPDATE oidc_sessions SET expires_at = now() - interval '1 day' WHERE id = ${uid}`);
    const longExpired = await make((uid) => testSql`UPDATE oidc_sessions SET expires_at = now() - interval '8 days' WHERE id = ${uid}`);
    const recentlyRevoked = await make((uid) => testSql`UPDATE oidc_sessions SET revoked_at = now() - interval '1 day' WHERE id = ${uid}`);
    const longRevoked = await make((uid) => testSql`UPDATE oidc_sessions SET revoked_at = now() - interval '8 days' WHERE id = ${uid}`);
    const alive = await make(async () => undefined);

    await purgeExpired();
    const left = new Set((await testSql`SELECT id FROM oidc_sessions WHERE id IN (${recentlyExpired}, ${longExpired}, ${recentlyRevoked}, ${longRevoked}, ${alive})`).map((row: any) => row.id));
    expect(left).toEqual(new Set([recentlyExpired, recentlyRevoked, alive]));
  });
});
