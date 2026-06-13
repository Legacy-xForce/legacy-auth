import { serve } from "bun";
import { config } from "./config.ts";
import { initDatabase, findUserByUsername, saveRefreshToken, findRefreshTokenByJti, verifyRefreshTokenHash, revokeRefreshToken } from "./db.ts";
import { getCachedUser, cacheUser, invalidateCachedUser } from "./cache.ts";
import { signAccessToken, signRefreshToken, verifyRefreshToken, getRefreshTokenExpiresAt } from "./jwt.ts";
import { getJwks } from "./keys.ts";
import { createOpenApiDocument } from "./openapi.ts";
import { createSwaggerAssetResponse, createSwaggerUiResponse, jsonHeaders } from "./swagger.ts";
import bcrypt from "bcryptjs";

const openApiDocument = createOpenApiDocument();

await initDatabase();

serve({
  port: config.port,
  fetch: async (request) => {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/openapi.json") {
        return new Response(JSON.stringify(openApiDocument), { status: 200, headers: jsonHeaders });
      }
      if (request.method === "GET" && url.pathname === "/docs") {
        return createSwaggerUiResponse();
      }
      if (request.method === "GET" && url.pathname.startsWith("/docs/")) {
        const asset = createSwaggerAssetResponse(url.pathname.slice("/docs/".length));
        if (!asset) {
          return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: jsonHeaders });
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
      if (request.method === "GET" && url.pathname === "/.well-known/jwks.json") {
        return new Response(JSON.stringify(getJwks()), { status: 200, headers: jsonHeaders });
      }
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: jsonHeaders });
    } catch (error) {
      console.error(error);
      const message = error instanceof Error ? error.message : "Internal server error";
      return new Response(JSON.stringify({ error: message }), { status: 500, headers: jsonHeaders });
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
    return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: jsonHeaders });
  }

  let user = getCachedUser(username);
  if (!user) {
    const record = await findUserByUsername(username);
    if (!record) {
      return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: jsonHeaders });
    }
    user = {
      id: record.id,
      username: record.username,
      password_hash: record.password_hash,
    };
    cacheUser(user);
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    return new Response(JSON.stringify({ error: "Invalid credentials" }), { status: 401, headers: jsonHeaders });
  }

  const accessToken = signAccessToken({ sub: user.id, username: user.username });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());

  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: jsonHeaders });
}

async function handleRefresh(request: Request) {
  const body = await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) {
    return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: jsonHeaders });
  }

  let payload;
  try {
    payload = verifyRefreshToken(rawToken);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: jsonHeaders });
  }

  const stored = await findRefreshTokenByJti(payload.jti);
  if (!stored || stored.revoked_at !== null) {
    return new Response(JSON.stringify({ error: "Invalid or revoked refresh token" }), { status: 401, headers: jsonHeaders });
  }
  if (new Date(stored.expires_at).getTime() < Date.now()) {
    return new Response(JSON.stringify({ error: "Refresh token expired" }), { status: 401, headers: jsonHeaders });
  }
  const validHash = await verifyRefreshTokenHash(rawToken, stored.token_hash);
  if (!validHash) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: jsonHeaders });
  }

  const accessToken = signAccessToken({ sub: payload.sub, username: payload.username });
  const refreshTokenMeta = signRefreshToken({ sub: payload.sub, username: payload.username });
  await revokeRefreshToken(payload.jti);
  await saveRefreshToken(payload.sub, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());

  return new Response(JSON.stringify({
    access_token: accessToken,
    refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: jsonHeaders });
}

async function handleLogout(request: Request) {
  const body = await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) {
    return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: jsonHeaders });
  }

  let payload;
  try {
    payload = verifyRefreshToken(rawToken);
  } catch (error) {
    return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: jsonHeaders });
  }

  await revokeRefreshToken(payload.jti);
  invalidateCachedUser(payload.username);

  return new Response(JSON.stringify({ success: true }), { status: 200, headers: jsonHeaders });
}
