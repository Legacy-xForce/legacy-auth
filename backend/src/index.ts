import { serve } from "bun";
import { config } from "./config.ts";
import { createCorsPreflightResponse, withCorsHeaders } from "./cors.ts";
import { initDatabase, findUserByUsername, findUserActiveByUsername, findUserById, saveRefreshToken, findRefreshTokenByJti, verifyRefreshTokenHash, revokeRefreshToken, revokeAllRefreshTokensForUser, updateUserPasswordHash, createUserWithActive, listUsersPaginated, updateUserProfile, updateUserScopes } from "./db.ts";
import { UserRecord, UserRole, UserScopes } from "./types.ts";
import { getCachedUser, cacheUser, invalidateCachedUser } from "./cache.ts";
import { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken, getRefreshTokenExpiresAt } from "./jwt.ts";
import { getJwks } from "./keys.ts";
import { createOpenApiDocument } from "./openapi.ts";
import { createSwaggerAssetResponse, createSwaggerUiResponse, jsonHeaders } from "./swagger.ts";
import { saveAvatar, findAvatar, UnsupportedImageError, UUID_PATTERN } from "./avatars.ts";
import { join, normalize } from "path";

const openApiDocument = createOpenApiDocument();

await initDatabase();

serve({
  port: config.port,
  fetch: async (request) => {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        return createCorsPreflightResponse(request);
      }
      if (request.method === "GET" && url.pathname === "/openapi.json") {
        return new Response(JSON.stringify(openApiDocument), { status: 200, headers: withCorsHeaders(jsonHeaders) });
      }
      if (request.method === "GET" && url.pathname === "/docs") {
        return createSwaggerUiResponse();
      }
      if (request.method === "GET" && url.pathname.startsWith("/docs/")) {
        const asset = createSwaggerAssetResponse(url.pathname.slice("/docs/".length));
        if (!asset) {
          return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
        }
        return asset;
      }
      if (request.method === "POST" && url.pathname === "/auth/login") {
        return await handleLogin(request);
      }
      if (request.method === "POST" && url.pathname === "/auth/refresh") {
        return await handleRefresh(request);
      }
      if (request.method === "POST" && url.pathname === "/auth/logout") {
        return await handleLogout(request);
      }
      if (request.method === "POST" && url.pathname === "/auth/change-password") {
        return await handleChangePassword(request);
      }
      if (request.method === "POST" && url.pathname === "/auth/profile-picture") {
        return await handleUploadProfilePicture(request);
      }
      if (request.method === "GET" && url.pathname.startsWith("/auth/profile-picture/")) {
        return await handleGetProfilePicture(url.pathname.slice("/auth/profile-picture/".length));
      }
      if (request.method === "GET" && url.pathname === "/.well-known/jwks.json") {
        return new Response(JSON.stringify(getJwks()), { status: 200, headers: withCorsHeaders(jsonHeaders) });
      }
      if (request.method === "GET" && url.pathname === "/auth/me") {
        return await handleGetMe(request);
      }
      if (request.method === "PATCH" && url.pathname === "/auth/me") {
        return await handleUpdateMe(request);
      }
      if (request.method === "GET" && url.pathname === "/admin/users") {
        return await handleListUsers(request, url);
      }
      if (request.method === "POST" && url.pathname === "/admin/users") {
        return await handleCreateUser(request);
      }
      const userMatch = url.pathname.match(/^\/admin\/users\/([0-9a-f-]{36})$/i);
      if (userMatch) {
        if (request.method === "GET") {
          return await handleGetUser(request, userMatch[1]);
        }
        if (request.method === "PATCH") {
          return await handleUpdateUser(request, userMatch[1]);
        }
      }
      const userAvatarMatch = url.pathname.match(/^\/admin\/users\/([0-9a-f-]{36})\/avatar$/i);
      if (userAvatarMatch && request.method === "POST") {
        return await handleUploadUserAvatar(request, userAvatarMatch[1]);
      }
      if (request.method === "GET") {
        const staticResponse = await tryServeFrontend(url.pathname);
        if (staticResponse) {
          return staticResponse;
        }
      }
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "Internal server error";
      return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
    }
  },
});

async function parseJson<T>(request: Request): Promise<T> {
  return await request.json() as T;
}

async function handleLogin(request: Request) {
  const body = await parseJson<{ username?: string; password?: string }>(request);
  const username = String(body.username ?? "").trim();
  const password = String(body.password ?? "");
  if (!username || !password) {
    return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  let user = getCachedUser(username);
  if (user) {
    const status = await findUserActiveByUsername(username);
    if (!status) {
      invalidateCachedUser(username);
      return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
    }
    if (status.locked) {
      invalidateCachedUser(username);
      return new Response(JSON.stringify({ error: "Account locked" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
    }
    if (!status.active) {
      invalidateCachedUser(username);
      return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
    }
    user = {
      ...user,
      active: status.active,
      locked: status.locked,
    };
  } else {
    const record = await findUserByUsername(username);
    if (!record) {
      return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
    }
    if (record.locked) {
      return new Response(JSON.stringify({ error: "Account locked" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
    }
    if (!record.active) {
      return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
    }
    user = {
      id: record.id,
      username: record.username,
      password_hash: record.password_hash,
      role: record.role,
      active: record.active,
      locked: record.locked,
      scopes: record.scopes,
    };
    cacheUser(user);
  }

  const validPassword = await Bun.password.verify(password, user.password_hash);
  if (!validPassword) {
    return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  if (user.password_hash.startsWith("$2")) {
    const upgradedPasswordHash = await Bun.password.hash(password);
    const updatedUser = await updateUserPasswordHash(user.id, upgradedPasswordHash);
    if (updatedUser) {
      user = {
        id: updatedUser.id,
        username: updatedUser.username,
        password_hash: updatedUser.password_hash,
        role: updatedUser.role,
        active: updatedUser.active,
        locked: updatedUser.locked,
        scopes: updatedUser.scopes,
      };
      cacheUser(user);
    }
  }

  const accessToken = signAccessToken({ sub: user.id, username: user.username, role: user.role, scopes: user.scopes });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());

  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleRefresh(request: Request) {
  const body = await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) {
    return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  let payload;
  try {
    payload = verifyRefreshToken(rawToken);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const stored = await findRefreshTokenByJti(payload.jti);
  if (!stored || stored.revoked_at !== null) {
    return new Response(JSON.stringify({ error: "Invalid or revoked refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (new Date(stored.expires_at).getTime() < Date.now()) {
    return new Response(JSON.stringify({ error: "Refresh token expired" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  const validHash = await verifyRefreshTokenHash(rawToken, stored.token_hash);
  if (!validHash) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const user = await findUserById(payload.sub);
  if (!user) {
    await revokeRefreshToken(payload.jti);
    invalidateCachedUser(payload.username);
    return new Response(JSON.stringify({ error: "Invalid or revoked refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (user.locked) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(payload.username);
    return new Response(JSON.stringify({ error: "Account locked" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(payload.username);
    return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }

  const accessToken = signAccessToken({ sub: payload.sub, username: payload.username, role: user.role, scopes: user.scopes });
  const refreshTokenMeta = signRefreshToken({ sub: payload.sub, username: payload.username });
  await revokeRefreshToken(payload.jti);
  await saveRefreshToken(payload.sub, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());

  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleLogout(request: Request) {
  const body = await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) {
    return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  let payload;
  try {
    payload = verifyRefreshToken(rawToken);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  await revokeRefreshToken(payload.jti);
  invalidateCachedUser(payload.username);

  return new Response(JSON.stringify({ success: true }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleChangePassword(request: Request) {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) {
    return new Response(JSON.stringify({ error: "Authorization bearer token is required" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const body = await parseJson<{ current_password?: string; new_password?: string }>(request);
  const currentPassword = String(body.current_password ?? "");
  const newPassword = String(body.new_password ?? "");
  if (!currentPassword || !newPassword) {
    return new Response(JSON.stringify({ error: "current_password and new_password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }
  if (currentPassword === newPassword) {
    return new Response(JSON.stringify({ error: "new_password must be different from current_password" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  let user = await findUserById(payload.sub);
  if (!user) {
    return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (user.locked) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(user.username);
    return new Response(JSON.stringify({ error: "Account locked" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(user.username);
    return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }

  const validPassword = await Bun.password.verify(currentPassword, user.password_hash);
  if (!validPassword) {
    return new Response(JSON.stringify({ error: "Current password is invalid" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const newPasswordHash = await Bun.password.hash(newPassword);
  const updatedUser = await updateUserPasswordHash(user.id, newPasswordHash);
  if (!updatedUser) {
    return new Response(JSON.stringify({ error: "Failed to update password" }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }

  await revokeAllRefreshTokensForUser(updatedUser.id);
  invalidateCachedUser(updatedUser.username);

  return new Response(JSON.stringify({ success: true }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUploadProfilePicture(request: Request) {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) {
    return new Response(JSON.stringify({ error: "Authorization bearer token is required" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const user = await findUserById(payload.sub);
  if (!user) {
    return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (!user.active || user.locked) {
    return new Response(JSON.stringify({ error: user.locked ? "Account locked" : "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }

  return await performAvatarUpload(request, user.id);
}

async function performAvatarUpload(request: Request, userId: string): Promise<Response> {
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch (error) {
    return new Response(JSON.stringify({ error: "Request must be multipart/form-data" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const file = formData.get("file");
  if (!(file instanceof Blob) || file.size === 0) {
    return new Response(JSON.stringify({ error: "file is required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }
  if (file.size > config.avatarMaxUploadBytes) {
    return new Response(JSON.stringify({ error: `file exceeds maximum size of ${config.avatarMaxUploadBytes} bytes` }), { status: 413, headers: withCorsHeaders(jsonHeaders) });
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    const saved = await saveAvatar(userId, bytes);
    return new Response(JSON.stringify({ success: true, content_type: saved.contentType }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error) {
    if (error instanceof UnsupportedImageError) {
      return new Response(JSON.stringify({ error: error.message }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
    }
    return new Response(JSON.stringify({ error: "Invalid or corrupted image" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handleGetProfilePicture(userId: string) {
  if (!UUID_PATTERN.test(userId)) {
    return new Response(JSON.stringify({ error: "Invalid user id" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const avatar = await findAvatar(userId);
  if (!avatar) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }

  return new Response(Bun.file(avatar.path), {
    status: 200,
    headers: withCorsHeaders({
      "Content-Type": avatar.contentType,
      "Cache-Control": "public, max-age=300",
    }),
  });
}

async function tryServeFrontend(pathname: string): Promise<Response | null> {
  const decoded = decodeURIComponent(pathname);
  const relative = normalize(decoded).replace(/^(\.\.[/\\])+/, "").replace(/^\/+/, "");
  const candidate = join(config.frontendDistDir, relative || "index.html");

  const file = Bun.file(candidate);
  if (await file.exists()) {
    return new Response(file);
  }

  const indexFile = Bun.file(join(config.frontendDistDir, "index.html"));
  if (await indexFile.exists()) {
    return new Response(indexFile);
  }

  return null;
}

function unauthorized(message: string, status = 401) {
  return new Response(JSON.stringify({ error: message }), { status, headers: withCorsHeaders(jsonHeaders) });
}

async function authenticate(request: Request): Promise<UserRecord | Response> {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) {
    return unauthorized("Authorization bearer token is required");
  }

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (error) {
    return unauthorized("Invalid access token");
  }

  const user = await findUserById(payload.sub);
  if (!user) {
    return unauthorized("Invalid access token");
  }
  if (user.locked) {
    return unauthorized("Account locked", 403);
  }
  if (!user.active) {
    return unauthorized("Account disabled", 403);
  }
  return user;
}

async function authenticateAdmin(request: Request): Promise<UserRecord | Response> {
  const result = await authenticate(request);
  if (result instanceof Response) {
    return result;
  }
  if (result.role !== "admin") {
    return unauthorized("Admin role required", 403);
  }
  return result;
}

function toPublicUser(user: UserRecord) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    active: user.active,
    locked: user.locked,
    scopes: user.scopes,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

function normalizeRole(value: unknown): UserRole {
  return value === "admin" ? "admin" : "user";
}

async function handleGetMe(request: Request) {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;
  return new Response(JSON.stringify(toPublicUser(auth)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUpdateMe(request: Request) {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;

  const body = await parseJson<{ username?: string }>(request);
  const update: { username?: string } = {};
  if (body.username !== undefined) update.username = String(body.username).trim();

  if (Object.keys(update).length === 0) {
    return new Response(JSON.stringify(toPublicUser(auth)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  }

  try {
    const updated = await updateUserProfile(auth.id, update);
    if (!updated) {
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
    }
    invalidateCachedUser(auth.username);
    invalidateCachedUser(updated.username);
    return new Response(JSON.stringify(toPublicUser(updated)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to update profile";
    if (message.toLowerCase().includes("unique")) {
      return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
    }
    return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handleListUsers(request: Request, url: URL) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const page = Math.max(1, Math.trunc(Number(url.searchParams.get("page") ?? "1")) || 1);
  const pageSize = Math.min(100, Math.max(1, Math.trunc(Number(url.searchParams.get("pageSize") ?? "20")) || 20));
  const search = url.searchParams.get("q")?.trim() || undefined;
  const roleParam = url.searchParams.get("role");
  const role = roleParam === "admin" || roleParam === "user" ? roleParam : undefined;

  const { items, total } = await listUsersPaginated({ search, role, page, pageSize });
  return new Response(JSON.stringify({
    items: items.map(toPublicUser),
    total,
    page,
    pageSize,
  }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleCreateUser(request: Request) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const body = await parseJson<{ username?: string; password?: string; role?: string; active?: boolean }>(request);
  const username = String(body.username ?? "").trim();
  const password = String(body.password ?? "");
  if (!username || !password) {
    return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const role = normalizeRole(body.role);
  const active = body.active === undefined ? true : Boolean(body.active);

  try {
    const user = await createUserWithActive(username, password, active, { role });
    return new Response(JSON.stringify(toPublicUser(user)), { status: 201, headers: withCorsHeaders(jsonHeaders) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to create user";
    if (message.toLowerCase().includes("unique")) {
      return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
    }
    return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handleGetUser(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const user = await findUserById(id);
  if (!user) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }
  return new Response(JSON.stringify(toPublicUser(user)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUpdateUser(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const body = await parseJson<{
    username?: string;
    role?: string;
    active?: boolean;
    locked?: boolean;
    password?: string;
    scopes?: { calendar?: boolean; tracker?: boolean };
  }>(request);

  let user = await findUserById(id);
  if (!user) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }
  const previousUsername = user.username;

  const profileUpdate: { username?: string; role?: UserRole; active?: boolean; locked?: boolean } = {};
  if (body.username !== undefined) profileUpdate.username = String(body.username).trim();
  if (body.role !== undefined) profileUpdate.role = normalizeRole(body.role);
  if (body.active !== undefined) profileUpdate.active = Boolean(body.active);
  if (body.locked !== undefined) profileUpdate.locked = Boolean(body.locked);

  try {
    if (Object.keys(profileUpdate).length > 0) {
      const updated = await updateUserProfile(id, profileUpdate);
      if (updated) user = updated;
    }

    if (body.scopes !== undefined) {
      const scopes: UserScopes = { calendar: Boolean(body.scopes?.calendar), tracker: Boolean(body.scopes?.tracker) };
      const updated = await updateUserScopes(id, scopes);
      if (updated) user = updated;
    }

    if (body.password) {
      const passwordHash = await Bun.password.hash(String(body.password));
      const updated = await updateUserPasswordHash(id, passwordHash);
      if (updated) user = updated;
      await revokeAllRefreshTokensForUser(id);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to update user";
    if (message.toLowerCase().includes("unique")) {
      return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
    }
    return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }

  if (user.locked || !user.active) {
    await revokeAllRefreshTokensForUser(id);
  }
  invalidateCachedUser(previousUsername);
  invalidateCachedUser(user.username);

  return new Response(JSON.stringify(toPublicUser(user)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUploadUserAvatar(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const target = await findUserById(id);
  if (!target) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }

  return await performAvatarUpload(request, target.id);
}
