import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { pruneAuditNow, startAuditPruning } from "../src/audit-retention.ts";
import { insertAuthEvent } from "../src/db.ts";
import { call, createTestUser, loginOk, startApp, testSql, type TestApp } from "./helpers.ts";

let app: TestApp;
let adminToken: string;

beforeAll(async () => {
  app = startApp();
  adminToken = (await loginOk(app, await createTestUser({ role: "admin" }))).access_token;
});
afterAll(() => app.stop());

const tag = () => `retention-${Math.random().toString(16).slice(2, 10)}`;

/** Inserts an event and backdates it by `daysOld`. */
async function seed(username: string, event: string, daysOld: number, success = true) {
  await insertAuthEvent({ event, success, username });
  await testSql`
    UPDATE auth_events SET created_at = now() - make_interval(days => ${daysOld})
    WHERE id = (SELECT max(id) FROM auth_events WHERE username = ${username})`;
}

const remaining = async (username: string) =>
  (await testSql<{ event: string }[]>`SELECT event FROM auth_events WHERE username = ${username} ORDER BY created_at`).map((row) => row.event);

describe("pruning", () => {
  test("deletes rows older than the retention period and keeps newer ones", async () => {
    const name = tag();
    await seed(name, "ancient", 400);
    await seed(name, "old", 181);
    await seed(name, "recent", 179);
    await seed(name, "fresh", 0);

    const removed = await pruneAuditNow(180);
    expect(removed).toBeGreaterThanOrEqual(2);
    expect(await remaining(name)).toEqual(["recent", "fresh"]);
  });

  test("honours a custom retention period", async () => {
    const name = tag();
    await seed(name, "ten-days", 10);
    await seed(name, "two-days", 2);
    await pruneAuditNow(7);
    expect(await remaining(name)).toEqual(["two-days"]);
  });

  test("0 days keeps everything", async () => {
    const name = tag();
    await seed(name, "ancient", 5000);
    expect(await pruneAuditNow(0)).toBe(0);
    expect(await remaining(name)).toEqual(["ancient"]);
  });

  test("does nothing, and returns 0, when there is nothing to prune", async () => {
    await pruneAuditNow(180);
    expect(await pruneAuditNow(180)).toBe(0);
  });

  test("the scheduled job prunes at once and can be stopped", async () => {
    const name = tag();
    await seed(name, "ancient", 1000);
    const stop = startAuditPruning(60_000);
    try {
      for (let attempt = 0; attempt < 50 && (await remaining(name)).length > 0; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, 40));
      }
      expect(await remaining(name)).toEqual([]);
    } finally {
      stop();
    }
  });
});

describe("GET /admin/audit-events", () => {
  test("requires an admin", async () => {
    expect((await call(app, "GET", "/admin/audit-events")).status).toBe(401);
    const plain = (await loginOk(app, await createTestUser())).access_token;
    expect((await call(app, "GET", "/admin/audit-events", { token: plain })).status).toBe(403);
  });

  test("lists newest first and reports the retention period", async () => {
    const name = tag();
    await seed(name, "first", 3);
    await seed(name, "second", 2);
    await seed(name, "third", 1);
    const result = await call(app, "GET", `/admin/audit-events?username=${name}`, { token: adminToken });
    expect(result.status).toBe(200);
    expect(result.body.items.map((row: any) => row.event)).toEqual(["third", "second", "first"]);
    expect(result.body.total).toBe(3);
    expect(typeof result.body.retention_days).toBe("number");
  });

  test("filters by event, outcome and (case-insensitive) username", async () => {
    const name = tag();
    await seed(name, "login", 1, true);
    await seed(name, "login", 1, false);
    await seed(name, "refresh", 1, false);
    const failedLogins = await call(app, "GET", `/admin/audit-events?username=${name.toUpperCase()}&event=login&success=false`, { token: adminToken });
    expect(failedLogins.body.total).toBe(1);
    expect(failedLogins.body.items[0]).toMatchObject({ event: "login", success: false, username: name });
    const allFailed = await call(app, "GET", `/admin/audit-events?username=${name}&success=false`, { token: adminToken });
    expect(allFailed.body.total).toBe(2);
  });

  test("filters by user id", async () => {
    const user = await createTestUser();
    await insertAuthEvent({ event: "login", success: true, userId: user.id, username: user.username });
    const result = await call(app, "GET", `/admin/audit-events?userId=${user.id}`, { token: adminToken });
    expect(result.body.items.every((row: any) => row.user_id === user.id)).toBe(true);
    expect(result.body.total).toBeGreaterThanOrEqual(1);
  });

  test("filters by time window: since is inclusive, until exclusive", async () => {
    const name = tag();
    await seed(name, "old", 10);
    await seed(name, "mid", 5);
    await seed(name, "new", 1);
    const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
    const until = new Date(Date.now() - 2 * 86_400_000).toISOString();
    const result = await call(app, "GET", `/admin/audit-events?username=${name}&since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`, { token: adminToken });
    expect(result.body.items.map((row: any) => row.event)).toEqual(["mid"]);
  });

  test("paginates", async () => {
    const name = tag();
    for (let i = 0; i < 5; i++) await seed(name, `e${i}`, 5 - i);
    const first = await call(app, "GET", `/admin/audit-events?username=${name}&pageSize=2&page=1`, { token: adminToken });
    const third = await call(app, "GET", `/admin/audit-events?username=${name}&pageSize=2&page=3`, { token: adminToken });
    expect(first.body.items).toHaveLength(2);
    expect(first.body.total).toBe(5);
    expect(third.body.items).toHaveLength(1);
    expect(first.body.items[0].event).toBe("e4");
  });

  test("caps the page size at 200", async () => {
    const result = await call(app, "GET", "/admin/audit-events?pageSize=100000", { token: adminToken });
    expect(result.body.pageSize).toBe(200);
  });

  test.each([
    ["success=maybe", "success"],
    ["userId=not-a-uuid", "userId"],
    ["since=yesterday", "since"],
    ["until=nope", "until"],
  ])("rejects a malformed filter (%s)", async (query, field) => {
    const result = await call(app, "GET", `/admin/audit-events?${query}`, { token: adminToken });
    expect(result.status).toBe(400);
    expect(result.body.error).toContain(field);
  });

  test("is safe against SQL in a filter value", async () => {
    const result = await call(app, "GET", `/admin/audit-events?event=${encodeURIComponent("x'; DROP TABLE auth_events; --")}`, { token: adminToken });
    expect(result.status).toBe(200);
    expect(result.body.total).toBe(0);
    const [{ count }] = await testSql<{ count: string }[]>`SELECT COUNT(*)::text AS count FROM auth_events`;
    expect(Number(count)).toBeGreaterThan(0);
  });
});
