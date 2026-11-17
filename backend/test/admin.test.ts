import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import sharp from "sharp";
import { config } from "../src/config.ts";
import { migrateAvatars } from "../src/avatars.ts";
import { call, createTestUser, login, loginOk, startApp, testSql, verifyWithJwks, type TestApp } from "./helpers.ts";

let app: TestApp;
let adminToken: string;
let adminId: string;

beforeAll(async () => {
  app = startApp();
  const admin = await createTestUser({ role: "admin" });
  adminId = admin.id;
  adminToken = (await loginOk(app, admin)).access_token;
});
afterAll(() => app.stop());

// 1x1 transparent PNG
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "base64");
// 2-frame animated GIF (16x16, red then blue)
const ANIMATED_GIF = Buffer.from("R0lGODlhEAAQAIAAAExpcf8AACH/C05FVFNDQVBFMi4wAwEAAAAh+QQFCgAAACwAAAAAEAAQAAACDoyPqcvtD6OctNqLsz4FACH5BAUAAAAALAAAAAAQABAAgExpcQAA/wIOjI+py+0Po5y02ouzPgUAOw==", "base64");

function imageForm(bytes: Uint8Array, name = "pic.png", type = "image/png") {
  const form = new FormData();
  form.set("file", new Blob([bytes], { type }), name);
  return form;
}

describe("authorization", () => {
  test("rejects a missing token (401) and a non-admin (403)", async () => {
    expect((await call(app, "GET", "/admin/users")).status).toBe(401);
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    expect((await call(app, "GET", "/admin/users", { token })).status).toBe(403);
    expect((await call(app, "POST", "/admin/users", { token, json: { username: "x", password: "y" } })).status).toBe(403);
    expect((await call(app, "PATCH", `/admin/users/${user.id}`, { token, json: { role: "admin" } })).status).toBe(403);
    expect((await call(app, "DELETE", `/admin/users/${user.id}`, { token })).status).toBe(403);
  });

  test("rejects a garbage bearer token", async () => {
    expect((await call(app, "GET", "/admin/users", { token: "garbage" })).status).toBe(401);
  });

  test("an admin who is later demoted loses access immediately", async () => {
    const admin = await createTestUser({ role: "admin" });
    const token = (await loginOk(app, admin)).access_token;
    expect((await call(app, "GET", "/admin/users", { token })).status).toBe(200);
    await testSql`UPDATE users SET role = 'user' WHERE id = ${admin.id}`;
    expect((await call(app, "GET", "/admin/users", { token })).status).toBe(403);
  });
});

describe("users", () => {
  test("creates a user who can sign in, and refuses a duplicate username", async () => {
    const username = `created${Math.random().toString(16).slice(2, 8)}`;
    const created = await call(app, "POST", "/admin/users", { token: adminToken, json: { username, password: "initial-pw", role: "user" } });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ username, display_name: username, role: "user", active: true, scopes: { calendar: false, tracker: false } });
    expect(created.body.password_hash).toBeUndefined();
    expect((await login(app, { id: created.body.id, username, password: "initial-pw" })).status).toBe(200);

    const dup = await call(app, "POST", "/admin/users", { token: adminToken, json: { username, password: "other" } });
    expect(dup.status).toBe(409);
  });

  test("lowercases usernames while keeping the typed name as the display name", async () => {
    const tag = Math.random().toString(16).slice(2, 8);
    const typed = `NewPerson-${tag}`;
    const created = await call(app, "POST", "/admin/users", {
      token: adminToken,
      json: { username: typed, display_name: "New Person", password: "case-pw" },
    });
    expect(created.status).toBe(201);
    expect(created.body.username).toBe(typed.toLowerCase());
    expect(created.body.display_name).toBe("New Person");

    // Signing in works with any capitalization, but the token keeps the canonical name.
    const signedIn = await login(app, { id: created.body.id, username: typed.toUpperCase(), password: "case-pw" });
    expect(signedIn.status).toBe(200);
    expect(verifyWithJwks(signedIn.body.access_token)).toMatchObject({ username: typed.toLowerCase(), display_name: "New Person" });

    // The same account cannot be created again under another casing.
    const dup = await call(app, "POST", "/admin/users", { token: adminToken, json: { username: typed.toLowerCase(), password: "other" } });
    expect(dup.status).toBe(409);

    // Renaming without an explicit display name adopts the capitalization typed for the new username.
    const renamed = await call(app, "PATCH", `/admin/users/${created.body.id}`, {
      token: adminToken,
      json: { username: `Renamed-${tag}` },
    });
    expect(renamed.body).toMatchObject({ username: `renamed-${tag}`, display_name: `Renamed-${tag}` });
  });

  test("an admin can change only the display name", async () => {
    const user = await createTestUser();
    const changed = await call(app, "PATCH", `/admin/users/${user.id}`, {
      token: adminToken,
      json: { display_name: "A Friendlier Name" },
    });
    expect(changed.body).toMatchObject({ username: user.username, display_name: "A Friendlier Name" });
    expect((await login(app, user)).body.access_token).toBeString();
  });

  test("validates required fields", async () => {
    expect((await call(app, "POST", "/admin/users", { token: adminToken, json: { username: "only-name" } })).status).toBe(400);
  });

  test("lists with search, role filter and pagination", async () => {
    const tag = Math.random().toString(16).slice(2, 8);
    for (let i = 0; i < 3; i++) {
      await call(app, "POST", "/admin/users", { token: adminToken, json: { username: `list-${tag}-${i}`, password: "pw", role: i === 0 ? "admin" : "user" } });
    }
    const all = await call(app, "GET", `/admin/users?q=list-${tag}&pageSize=2&page=1`, { token: adminToken });
    expect(all.body.total).toBe(3);
    expect(all.body.items).toHaveLength(2);
    const page2 = await call(app, "GET", `/admin/users?q=list-${tag}&pageSize=2&page=2`, { token: adminToken });
    expect(page2.body.items).toHaveLength(1);
    const admins = await call(app, "GET", `/admin/users?q=list-${tag}&role=admin`, { token: adminToken });
    expect(admins.body.total).toBe(1);
    expect(admins.body.items[0].password_hash).toBeUndefined();
  });

  test("gets one user, and 404s for an unknown id", async () => {
    const user = await createTestUser();
    expect((await call(app, "GET", `/admin/users/${user.id}`, { token: adminToken })).body.username).toBe(user.username);
    expect((await call(app, "GET", "/admin/users/00000000-0000-0000-0000-000000000000", { token: adminToken })).status).toBe(404);
  });

  test("updating scopes shows up in the user's next token", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    const updated = await call(app, "PATCH", `/admin/users/${user.id}`, { token: adminToken, json: { scopes: { calendar: true, tracker: false } } });
    expect(updated.body.scopes).toEqual({ calendar: true, tracker: false });
    const refreshed = await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } });
    expect(verifyWithJwks(refreshed.body.access_token).scopes).toEqual({ calendar: true, tracker: false });
  });

  test("setting a password revokes every session and the new password works", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    await call(app, "PATCH", `/admin/users/${user.id}`, { token: adminToken, json: { password: "admin-set-pw" } });
    expect((await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } })).status).toBe(401);
    expect((await login(app, { ...user, password: "admin-set-pw" })).status).toBe(200);
  });

  test("deactivating revokes sessions and blocks sign-in", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    await call(app, "PATCH", `/admin/users/${user.id}`, { token: adminToken, json: { active: false } });
    expect((await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } })).status).toBe(401);
    expect((await login(app, user)).status).toBe(403);
    // a still-valid access token of a disabled account is refused too
    expect((await call(app, "GET", "/auth/me", { token: tokens.access_token })).status).toBe(403);
  });

  test("renaming works and a taken name is a 409", async () => {
    const a = await createTestUser();
    const b = await createTestUser();
    expect((await call(app, "PATCH", `/admin/users/${a.id}`, { token: adminToken, json: { username: b.username } })).status).toBe(409);
    const fresh = `renamed${Math.random().toString(16).slice(2, 8)}`;
    expect((await call(app, "PATCH", `/admin/users/${a.id}`, { token: adminToken, json: { username: fresh } })).body.username).toBe(fresh);
  });

  test("deletes a user, but never the caller's own account", async () => {
    const user = await createTestUser();
    const tokens = await loginOk(app, user);
    expect((await call(app, "DELETE", `/admin/users/${user.id}`, { token: adminToken })).status).toBe(204);
    expect((await call(app, "GET", `/admin/users/${user.id}`, { token: adminToken })).status).toBe(404);
    expect((await call(app, "POST", "/auth/refresh", { json: { refresh_token: tokens.refresh_token } })).status).toBe(401);
    expect((await call(app, "DELETE", `/admin/users/${adminId}`, { token: adminToken })).status).toBe(400);
  });
});

describe("own profile and avatars", () => {
  test("GET/PATCH /auth/me", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    expect((await call(app, "GET", "/auth/me", { token })).body).toMatchObject({ username: user.username, display_name: user.displayName ?? user.username });
    const fresh = `me${Math.random().toString(16).slice(2, 8)}`;
    expect((await call(app, "PATCH", "/auth/me", { token, json: { username: fresh } })).body.username).toBe(fresh);
    const display = await call(app, "PATCH", "/auth/me", { token, json: { display_name: "My Name" } });
    expect(display.body).toMatchObject({ username: fresh, display_name: "My Name" });
  });

  test("a user cannot raise their own role or scopes through /auth/me", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    const result = await call(app, "PATCH", "/auth/me", { token, json: { role: "admin", scopes: { calendar: true, tracker: true } } });
    expect(result.body.role).toBe("user");
    expect(result.body.scopes).toEqual({ calendar: false, tracker: false });
  });

  test("uploads and serves a profile picture", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    const response = await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: imageForm(PNG) });
    expect(response.status).toBe(200);
    const { content_type } = await response.json();
    expect(content_type).toBe("image/webp");
    const image = await fetch(`${app.url}/auth/profile-picture/${user.id}`);
    expect(image.status).toBe(200);
    expect(image.headers.get("content-type")).toBe(content_type);
  });

  test("keeps animated pictures animated as WebP", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    const upload = await fetch(`${app.url}/auth/profile-picture`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}` },
      body: imageForm(ANIMATED_GIF, "anim.gif", "image/gif"),
    });
    expect(upload.status).toBe(200);
    expect((await upload.json()).content_type).toBe("image/webp");

    const image = await fetch(`${app.url}/auth/profile-picture/${user.id}`);
    expect(image.headers.get("content-type")).toBe("image/webp");
    const bytes = new Uint8Array(await image.arrayBuffer());
    expect((await sharp(bytes, { animated: true }).metadata()).pages).toBe(2);
  });

  test("still serves a legacy GIF until it is replaced", async () => {
    const user = await createTestUser();
    const legacy = `${config.avatarStorageDir}/${user.id}.gif`;
    await Bun.write(legacy, ANIMATED_GIF);
    expect((await fetch(`${app.url}/auth/profile-picture/${user.id}`)).headers.get("content-type")).toBe("image/gif");

    const token = (await loginOk(app, user)).access_token;
    await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: imageForm(PNG) });
    expect((await fetch(`${app.url}/auth/profile-picture/${user.id}`)).headers.get("content-type")).toBe("image/webp");
    expect(await Bun.file(legacy).exists()).toBe(false);
  });

  test("serves an ETag and answers conditional requests with 304", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    const url = `${app.url}/auth/profile-picture/${user.id}`;
    expect((await fetch(url)).status).toBe(404);

    await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: imageForm(PNG) });
    const first = await fetch(url);
    const etag = first.headers.get("etag");
    expect(etag).toBeTruthy();
    expect(first.status).toBe(200);

    const revalidated = await fetch(url, { headers: { "if-none-match": etag! } });
    expect(revalidated.status).toBe(304);
    expect(revalidated.headers.get("etag")).toBe(etag);
    expect(await revalidated.text()).toBe("");

    // A new upload changes the file, so the old validator must not match.
    await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: imageForm(ANIMATED_GIF, "anim.gif", "image/gif") });
    const changed = await fetch(url, { headers: { "if-none-match": etag! } });
    expect(changed.status).toBe(200);
    expect(changed.headers.get("etag")).not.toBe(etag);
  });

  test("migrates legacy JPEG/GIF avatars to WebP", async () => {
    const stillUser = await createTestUser();
    const animatedUser = await createTestUser();
    const avifUser = await createTestUser();
    const stillLegacy = `${config.avatarStorageDir}/${stillUser.id}.jpg`;
    const animatedLegacy = `${config.avatarStorageDir}/${animatedUser.id}.gif`;
    const avifLegacy = `${config.avatarStorageDir}/${avifUser.id}.avif`;
    await Bun.write(stillLegacy, PNG);
    await Bun.write(animatedLegacy, ANIMATED_GIF);
    await Bun.write(avifLegacy, await sharp(PNG).avif().toBuffer());

    const result = await migrateAvatars();
    expect(result.converted).toContain(`${stillUser.id}.jpg`);
    expect(result.converted).toContain(`${animatedUser.id}.gif`);
    expect(result.converted).toContain(`${avifUser.id}.avif`);
    expect(await Bun.file(stillLegacy).exists()).toBe(false);
    expect(await Bun.file(animatedLegacy).exists()).toBe(false);
    expect(await Bun.file(avifLegacy).exists()).toBe(false);

    const still = await fetch(`${app.url}/auth/profile-picture/${stillUser.id}`);
    expect(still.headers.get("content-type")).toBe("image/webp");
    const animated = await fetch(`${app.url}/auth/profile-picture/${animatedUser.id}`);
    expect(animated.headers.get("content-type")).toBe("image/webp");
    const bytes = new Uint8Array(await animated.arrayBuffer());
    expect((await sharp(bytes, { animated: true }).metadata()).pages).toBe(2);
    expect((await fetch(`${app.url}/auth/profile-picture/${avifUser.id}`)).headers.get("content-type")).toBe("image/webp");

    // Re-running is a no-op.
    const second = await migrateAvatars();
    expect(second.converted).not.toContain(`${stillUser.id}.jpg`);
  });

  test("serves the Scalar API reference pointed at the generated spec", async () => {
    const docs = await fetch(`${app.url}/docs`);
    expect(docs.status).toBe(200);
    expect(docs.headers.get("content-type")).toContain("text/html");
    const html = await docs.text();
    expect(html.toLowerCase()).toContain("scalar");
    expect(html).toContain("/openapi.json");
  });

  test("rejects a file that is not an image, and a missing file", async () => {
    const user = await createTestUser();
    const token = (await loginOk(app, user)).access_token;
    const bad = await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: imageForm(new TextEncoder().encode("not an image"), "x.png") });
    expect(bad.status).toBe(400);
    const empty = await fetch(`${app.url}/auth/profile-picture`, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: new FormData() });
    expect(empty.status).toBe(400);
  });

  test("an admin can set another user's picture; a plain user cannot", async () => {
    const target = await createTestUser();
    const ok = await fetch(`${app.url}/admin/users/${target.id}/avatar`, { method: "POST", headers: { authorization: `Bearer ${adminToken}` }, body: imageForm(PNG) });
    expect(ok.status).toBe(200);
    const plain = await createTestUser();
    const plainToken = (await loginOk(app, plain)).access_token;
    const denied = await fetch(`${app.url}/admin/users/${target.id}/avatar`, { method: "POST", headers: { authorization: `Bearer ${plainToken}` }, body: imageForm(PNG) });
    expect(denied.status).toBe(403);
  });

  test("returns 404 for a user with no picture and 400 for a malformed id", async () => {
    const user = await createTestUser();
    expect((await fetch(`${app.url}/auth/profile-picture/${user.id}`)).status).toBe(404);
    expect((await fetch(`${app.url}/auth/profile-picture/not-a-uuid`)).status).toBe(400);
  });
});
