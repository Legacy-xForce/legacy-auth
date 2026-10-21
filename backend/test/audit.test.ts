import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { call, createTestUser, login, loginOk, startApp, testSql, type TestApp } from "./helpers.ts";

let app: TestApp;
beforeAll(() => {
  app = startApp();
});
afterAll(() => app.stop());

type EventRow = { event: string; success: boolean; user_id: string | null; username: string | null; actor_id: string | null; detail: string | null; user_agent: string | null };

/** Audit rows are written without holding up the request, so wait for them. */
async function eventsFor(username: string, expected = 1): Promise<EventRow[]> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const rows = await testSql<EventRow[]>`SELECT event, success, user_id, username, actor_id, detail, user_agent FROM auth_events WHERE username = ${username} ORDER BY id`;
    if (rows.length >= expected) return rows;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return testSql<EventRow[]>`SELECT event, success, user_id, username, actor_id, detail, user_agent FROM auth_events WHERE username = ${username} ORDER BY id`;
}

describe("auth_events", () => {
  test("records successful and failed sign-ins", async () => {
    const user = await createTestUser();
    await login(app, { ...user, password: "wrong" });
    await login(app, user);
    const rows = await eventsFor(user.username, 2);
    expect(rows.map((row) => [row.event, row.success])).toEqual([
      ["login", false],
      ["login", true],
    ]);
    expect(rows[0].detail).toBe("Invalid credentials");
    expect(rows[0].user_id).toBe(user.id);
  });

  test("never records the password or tokens", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    await login(app, { ...user, password: "super-secret-wrong-guess" });
    const rows = await eventsFor(user.username, 2);
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(user.password);
    expect(dump).not.toContain("super-secret-wrong-guess");
    expect(dump).not.toContain(tokens.access_token);
    expect(dump).not.toContain(tokens.refresh_token);
  });

  test("records failed refreshes, password changes and the user agent", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    await call(app, "POST", "/auth/logout", { json: { refresh_token: tokens.refresh_token } });
    await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } });
    await call(app, "POST", "/auth/change-password", {
      token: tokens.access_token,
      headers: { "user-agent": "audit-test/1.0" },
      json: { current_password: user.password, new_password: "another-secret" },
    });
    const rows = await eventsFor(user.username, 3);
    const byEvent = Object.fromEntries(rows.map((row) => [row.event, row]));
    expect(byEvent.refresh.success).toBe(false);
    expect(byEvent.password_change.success).toBe(true);
    expect(byEvent.password_change.user_agent).toBe("audit-test/1.0");
  });

  test("records admin changes with the acting admin", async () => {
    const admin = await createTestUser({ role: "admin" });
    const adminToken = (await loginOk(app, admin)).access_token;
    const target = await createTestUser();
    await call(app, "PATCH", `/admin/users/${target.id}`, { token: adminToken, json: { scopes: { calendar: true } } });
    const rows = await eventsFor(target.username);
    const update = rows.find((row) => row.event === "admin_user_update");
    expect(update?.actor_id).toBe(admin.id);
    expect(update?.detail).toContain("scopes=calendar:true");
  });
});
