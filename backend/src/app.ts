import { config } from "./config.ts";
import { applyCorsOrigin, createCorsPreflightResponse, withCorsHeaders } from "./cors.ts";
import { findUserByUsername, findUserActiveByUsername, findUserById, saveRefreshToken, findRefreshTokenByJti, verifyRefreshTokenHash, claimRefreshToken, revokeRefreshFamily, revokeRefreshToken, revokeAllRefreshTokensForUser, updateUserPasswordHash, createUserWithActive, listUsersPaginated, updateUserProfile, updateUserScopes, deleteUserById, insertAuthEvent, listAuthEvents, AuthEvent } from "./db.ts";
import { APP_AUDIENCES, UserRecord, UserRole, UserScopes } from "./types.ts";
import { displayNameFromInput, normalizeUsername } from "./usernames.ts";
import { getCachedUser, cacheUser, invalidateCachedUser } from "./cache.ts";
import { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken, getRefreshTokenExpiresAt, resolveAudience, AudienceError } from "./jwt.ts";
import { throttleKeys, retryAfterSeconds, recordFailure, clearUserFailures, isPrivateAddress } from "./throttle.ts";
import { getJwks } from "./keys.ts";
import { assetLinks } from "./asset-links.ts";
import { createOpenApiDocument } from "./openapi.ts";
import { createSwaggerAssetResponse, createSwaggerUiResponse, jsonHeaders } from "./swagger.ts";
import { oidc } from "./oidc/index.ts";
import { handleOidcAdmin } from "./oidc/admin.ts";
import { saveAvatar, findAvatar, deleteAvatar, UnsupportedImageError, UUID_PATTERN } from "./avatars.ts";
import {
  generateLoginOptions,
  verifyLogin,
  generateRegisterOptions,
  verifyRegister,
  listCredentials,
  deleteCredential,
} from "./passkey.ts";
import { join, normalize } from "path";


const openApiDocument = createOpenApiDocument();

/** What the handlers need from the HTTP server: the socket address of a request. */
export type PeerLookup = { requestIP(request: Request): { address: string } | null };

let server: PeerLookup | undefined;

/** Gives the handlers the server that is serving them, so they can read client addresses. */
export function bindServer(bound: PeerLookup) {
  server = bound;
}

/**
 * The Resource Owner Password Credentials endpoints, which the OpenID Provider
 * replaces. They keep working (and keep honouring `audience`) for one release
 * cycle so clients can move; every response from them says so.
 */
const DEPRECATED_LOGIN_ENDPOINTS = new Set(["POST /auth/login", "POST /auth/passkey/login-options", "POST /auth/passkey/login-verify"]);

function markDeprecated(request: Request, response: Response): Response {
  if (DEPRECATED_LOGIN_ENDPOINTS.has(`${request.method} ${new URL(request.url).pathname}`)) {
    response.headers.set("Deprecation", "true");
    response.headers.set("Link", `<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  }
  return response;
}

export async function handleRequest(request: Request): Promise<Response> {
  const response = markDeprecated(request, await route(request));
  // The OP decides its own CORS per client (a public client may call /token from its redirect URIs' origins);
  // the legacy allowlist, which only names the origins of the old login, must not overwrite or hide that.
  return oidc.handles(new URL(request.url).pathname) ? response : applyCorsOrigin(request, response);
}

async function route(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (request.method === "OPTIONS" && !oidc.handles(url.pathname)) {
      return createCorsPreflightResponse(request);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
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
    if (oidc.handles(url.pathname)) {
      return await oidc.handle(request, clientIp(request));
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
    if (request.method === "POST" && url.pathname === "/auth/passkey/login-options") {
      return await handlePasskeyLoginOptions(request);
    }
    if (request.method === "POST" && url.pathname === "/auth/passkey/login-verify") {
      return await handlePasskeyLoginVerify(request);
    }
    if (request.method === "POST" && url.pathname === "/auth/passkey/register-options") {
      return await handlePasskeyRegisterOptions(request);
    }
    if (request.method === "POST" && url.pathname === "/auth/passkey/register-verify") {
      return await handlePasskeyRegisterVerify(request);
    }
    if (request.method === "GET" && url.pathname === "/auth/passkey/credentials") {
      return await handlePasskeyListCredentials(request);
    }
    const passkeyCredentialMatch = url.pathname.match(/^\/auth\/passkey\/credentials\/([A-Za-z0-9_-]+)$/);
    if (passkeyCredentialMatch && request.method === "DELETE") {
      return await handlePasskeyDeleteCredential(request, passkeyCredentialMatch[1]);
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
    if (request.method === "GET" && url.pathname === "/.well-known/assetlinks.json") {
      const statements = assetLinks();
      if (statements) {
        return new Response(JSON.stringify(statements), { status: 200, headers: withCorsHeaders(jsonHeaders) });
      }
    }
    if (request.method === "GET" && url.pathname === "/auth/me") {
      return await handleGetMe(request);
    }
    if (request.method === "PATCH" && url.pathname === "/auth/me") {
      return await handleUpdateMe(request);
    }
    if (url.pathname.startsWith("/admin/oidc/")) {
      const auth = await authenticateAdmin(request);
      if (auth instanceof Response) return auth;
      const response = await handleOidcAdmin({ request, url, actor: auth, audit: (entry) => audit(request, entry) });
      if (response) return response;
    }
    if (request.method === "GET" && url.pathname === "/admin/audit-events") {
      return await handleListAuditEvents(request, url);
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
      if (request.method === "DELETE") {
        return await handleDeleteUser(request, userMatch[1]);
      }
    }
    const userAvatarMatch = url.pathname.match(/^\/admin\/users\/([0-9a-f-]{36})\/avatar$/i);
    if (userAvatarMatch && request.method === "POST") {
      return await handleUploadUserAvatar(request, userAvatarMatch[1]);
    }
    if (
      request.method === "GET" &&
      !url.pathname.startsWith("/auth/") &&
      !url.pathname.startsWith("/admin/") &&
      !url.pathname.startsWith("/.well-known/")
    ) {
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
}

async function parseJson<T>(request: Request): Promise<T> {
  return await request.json() as T;
}

function clientIp(request: Request): string | null {
  const peer = server?.requestIP(request)?.address ?? null;
  // Forwarded headers are believed only from a proxy on a private address: a
  // client reaching the port directly could otherwise claim any IP.
  if (config.trustProxy && peer && isPrivateAddress(peer)) {
    // Each proxy appends what it saw, so the rightmost public entry comes from
    // the outermost proxy (e.g. Cloudflare); anything left of it is whatever
    // the client sent.
    const forwarded = (request.headers.get("x-forwarded-for") ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    for (let i = forwarded.length - 1; i >= 0; i--) {
      if (!isPrivateAddress(forwarded[i])) return forwarded[i];
    }
  }
  return peer;
}

/**
 * The client address to count failed sign-ins against, or `null` when all we
 * know is a proxy's private address (see isPrivateAddress).
 */
function throttleIp(request: Request): string | null {
  const ip = clientIp(request);
  return ip && !isPrivateAddress(ip) ? ip : null;
}

/** Records an auth event without holding up or failing the request. */
function audit(request: Request, entry: Omit<AuthEvent, "ip" | "userAgent">) {
  insertAuthEvent({ ...entry, ip: clientIp(request), userAgent: request.headers.get("user-agent") }).catch((error) => {
    console.error("[audit] failed to record auth event", error);
  });
}

function tooManyAttempts(retryAfter: number) {
  return new Response(JSON.stringify({ error: "Too many failed attempts, try again later" }), {
    status: 429,
    headers: withCorsHeaders({ ...jsonHeaders, "Retry-After": String(retryAfter) }),
  });
}

async function handleLogin(request: Request) {
  const body = await parseJson<{ username?: string; password?: string; audience?: string }>(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password ?? "");
  if (!username || !password) {
    return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const throttle = throttleKeys(throttleIp(request), username);
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(request, { event: "login", success: false, username, detail: "throttled" });
    return tooManyAttempts(retryAfter);
  }
  const reject = (error: string, status: number, userId?: string) => {
    recordFailure(throttle);
    audit(request, { event: "login", success: false, userId, username, detail: error });
    return new Response(JSON.stringify({ error }), { status, headers: withCorsHeaders(jsonHeaders) });
  };

  let user = getCachedUser(username);
  if (user) {
    const status = await findUserActiveByUsername(username);
    if (!status) {
      invalidateCachedUser(username);
      return reject("Invalid credentials", 401);
    }
    if (!status.active) {
      invalidateCachedUser(username);
      return reject("Account disabled", 403, status.id);
    }
    user = {
      ...user,
      active: status.active,
    };
  } else {
    const record = await findUserByUsername(username);
    if (!record) {
      return reject("Invalid credentials", 401);
    }
    if (!record.active) {
      return reject("Account disabled", 403, record.id);
    }
    user = {
      id: record.id,
      username: record.username,
      display_name: record.display_name,
      password_hash: record.password_hash,
      role: record.role,
      active: record.active,
      scopes: record.scopes,
    };
    cacheUser(user);
  }

  const validPassword = await Bun.password.verify(password, user.password_hash);
  if (!validPassword) {
    return reject("Invalid credentials", 401, user.id);
  }
  clearUserFailures(username);

  let audience;
  try {
    audience = resolveAudience(body.audience, user.scopes, { required: config.requireAudience });
  } catch (error) {
    if (!(error instanceof AudienceError)) throw error;
    audit(request, { event: "login", success: false, userId: user.id, username, detail: error.message });
    return new Response(JSON.stringify({ error: error.message }), { status: error.statusCode, headers: withCorsHeaders(jsonHeaders) });
  }

  if (user.password_hash.startsWith("$2")) {
    const upgradedPasswordHash = await Bun.password.hash(password);
    const updatedUser = await updateUserPasswordHash(user.id, upgradedPasswordHash);
    if (updatedUser) {
      user = {
        id: updatedUser.id,
        username: updatedUser.username,
        display_name: updatedUser.display_name,
        password_hash: updatedUser.password_hash,
        role: updatedUser.role,
        active: updatedUser.active,
        scopes: updatedUser.scopes,
      };
      cacheUser(user);
    }
  }

  const accessToken = signAccessToken({ sub: user.id, username: user.username, displayName: user.display_name, role: user.role, scopes: user.scopes, audience });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username, app: body.audience ? audience[0] : undefined });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());
  audit(request, { event: "login", success: true, userId: user.id, username: user.username, detail: audience.join(",") || null });

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
  // A rotated token may still be refreshed within the grace period, which
  // claimRefreshToken enforces below; an explicitly revoked one may not.
  if (!stored || (stored.revoked_at !== null && stored.rotated_at === null)) {
    audit(request, { event: "refresh", success: false, userId: stored?.user_id, username: payload.username, detail: "revoked or unknown token" });
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
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(payload.username);
    return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }

  // Scopes are re-read on every refresh, so losing an app's scope ends the
  // sessions opened for that app.
  let audience;
  try {
    audience = resolveAudience(payload.app, user.scopes);
  } catch (error) {
    if (!(error instanceof AudienceError)) throw error;
    await revokeRefreshToken(payload.jti);
    audit(request, { event: "refresh", success: false, userId: user.id, username: user.username, detail: error.message });
    return new Response(JSON.stringify({ error: error.message }), { status: error.statusCode, headers: withCorsHeaders(jsonHeaders) });
  }

  const family = stored.family_id ?? stored.id;
  const claim = await claimRefreshToken(payload.jti, config.refreshReuseGraceSeconds);
  if (!claim) {
    // A token that was already rotated, presented after the grace period: it was copied, or the
    // client is broken. Either way nothing in its family can be trusted any more.
    const revoked = await revokeRefreshFamily(family);
    audit(request, {
      event: "refresh_reuse",
      success: false,
      userId: user.id,
      username: user.username,
      detail: `rotated token presented outside the grace period; ${revoked} token(s) of its family revoked`,
    });
    return new Response(JSON.stringify({ error: "Invalid or revoked refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (claim === "grace") {
    audit(request, { event: "refresh", success: true, userId: user.id, username: user.username, detail: "reused within grace period" });
  }
  const accessToken = signAccessToken({ sub: payload.sub, username: user.username, displayName: user.display_name, role: user.role, scopes: user.scopes, audience });
  const refreshTokenMeta = signRefreshToken({ sub: payload.sub, username: user.username, app: payload.app });
  await saveRefreshToken(payload.sub, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt(), family);

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
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(user.username);
    return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  }

  const throttle = throttleKeys(throttleIp(request), user.username);
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(request, { event: "password_change", success: false, userId: user.id, username: user.username, detail: "throttled" });
    return tooManyAttempts(retryAfter);
  }
  const validPassword = await Bun.password.verify(currentPassword, user.password_hash);
  if (!validPassword) {
    recordFailure(throttle);
    audit(request, { event: "password_change", success: false, userId: user.id, username: user.username, detail: "Current password is invalid" });
    return new Response(JSON.stringify({ error: "Current password is invalid" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const newPasswordHash = await Bun.password.hash(newPassword);
  const updatedUser = await updateUserPasswordHash(user.id, newPasswordHash);
  if (!updatedUser) {
    return new Response(JSON.stringify({ error: "Failed to update password" }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }

  await revokeAllRefreshTokensForUser(updatedUser.id);
  await oidc.endUserSessions(updatedUser.id);
  invalidateCachedUser(updatedUser.username);
  audit(request, { event: "password_change", success: true, userId: updatedUser.id, username: updatedUser.username });

  return new Response(JSON.stringify({ success: true }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyLoginOptions(request: Request) {
  const body = await parseJson<{ username?: string }>(request).catch(() => ({} as { username?: string }));
  const username = typeof body.username === "string" && body.username.trim() ? normalizeUsername(body.username) : undefined;
  const options = await generateLoginOptions(username);
  return new Response(JSON.stringify(options), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyLoginVerify(request: Request) {
  const body = await parseJson<any>(request);
  // No username here, so passkey attempts are throttled per client IP only.
  const throttle = throttleKeys(throttleIp(request));
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(request, { event: "passkey_login", success: false, detail: "throttled" });
    return tooManyAttempts(retryAfter);
  }
  try {
    const result = await verifyLogin(body);
    audit(request, { event: "passkey_login", success: true, userId: result.user.id, username: result.user.username });
    return new Response(JSON.stringify(result), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error: any) {
    const status = error.statusCode || 401;
    if (status === 401) recordFailure(throttle);
    audit(request, { event: "passkey_login", success: false, detail: error.message || "Passkey verification failed" });
    return new Response(JSON.stringify({ error: error.message || "Passkey verification failed" }), {
      status,
      headers: withCorsHeaders(jsonHeaders),
    });
  }
}

async function handlePasskeyRegisterOptions(request: Request) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const options = await generateRegisterOptions(authResult);
  return new Response(JSON.stringify(options), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyRegisterVerify(request: Request) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const body = await parseJson<any>(request);
  try {
    const result = await verifyRegister(authResult.id, body);
    audit(request, { event: "passkey_register", success: true, userId: authResult.id, username: authResult.username, detail: result.credentialId });
    return new Response(JSON.stringify(result), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error: any) {
    const status = error.statusCode || 400;
    return new Response(JSON.stringify({ error: error.message || "Passkey registration failed" }), {
      status,
      headers: withCorsHeaders(jsonHeaders),
    });
  }
}

async function handlePasskeyListCredentials(request: Request) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const list = await listCredentials(authResult.id);
  return new Response(JSON.stringify(list), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyDeleteCredential(request: Request, id: string) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  try {
    const result = await deleteCredential(id, authResult.id);
    audit(request, { event: "passkey_delete", success: true, userId: authResult.id, username: authResult.username, detail: id });
    return new Response(JSON.stringify(result), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error: any) {
    const status = error.statusCode || 400;
    return new Response(JSON.stringify({ error: error.message || "Failed to delete passkey" }), {
      status,
      headers: withCorsHeaders(jsonHeaders),
    });
  }
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
  if (!user.active) {
    return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
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
    display_name: user.display_name,
    role: user.role,
    active: user.active,
    scopes: user.scopes,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

/** The fields an admin update touched, without the password itself. */
function describeUserUpdate(body: { username?: string; display_name?: string; role?: string; active?: boolean; password?: string; scopes?: { calendar?: boolean; tracker?: boolean } }) {
  const parts: string[] = [];
  if (body.username !== undefined) parts.push(`username=${normalizeUsername(body.username)}`);
  if (body.display_name !== undefined) parts.push(`display_name=${displayNameFromInput(body.display_name)}`);
  if (body.role !== undefined) parts.push(`role=${normalizeRole(body.role)}`);
  if (body.active !== undefined) parts.push(`active=${Boolean(body.active)}`);
  if (body.scopes !== undefined) parts.push(`scopes=calendar:${Boolean(body.scopes?.calendar)},tracker:${Boolean(body.scopes?.tracker)}`);
  if (body.password) parts.push("password=changed");
  return parts.join(" ") || null;
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

  const body = await parseJson<{ username?: string; display_name?: string }>(request);
  const update: { username?: string; displayName?: string } = {};
  if (body.username !== undefined) update.username = displayNameFromInput(body.username);
  if (body.display_name !== undefined) update.displayName = displayNameFromInput(body.display_name);

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

async function handleListAuditEvents(request: Request, url: URL) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const bad = (error: string) => new Response(JSON.stringify({ error }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  const params = url.searchParams;

  const page = Math.max(1, Math.trunc(Number(params.get("page") ?? "1")) || 1);
  const pageSize = Math.min(200, Math.max(1, Math.trunc(Number(params.get("pageSize") ?? "50")) || 50));

  const successParam = params.get("success");
  if (successParam !== null && successParam !== "true" && successParam !== "false") {
    return bad("success must be true or false");
  }
  const userId = params.get("userId");
  if (userId !== null && !UUID_PATTERN.test(userId)) {
    return bad("userId must be a UUID");
  }
  const dates: Record<"since" | "until", Date | undefined> = { since: undefined, until: undefined };
  for (const name of ["since", "until"] as const) {
    const raw = params.get(name);
    if (raw === null) continue;
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return bad(`${name} must be an ISO 8601 date`);
    dates[name] = parsed;
  }

  const { items, total } = await listAuthEvents({
    event: params.get("event") || undefined,
    success: successParam === null ? undefined : successParam === "true",
    userId: userId ?? undefined,
    username: params.get("username")?.trim() || undefined,
    since: dates.since,
    until: dates.until,
    page,
    pageSize,
  });
  return new Response(JSON.stringify({ items, total, page, pageSize, retention_days: config.auditRetentionDays }), {
    status: 200,
    headers: withCorsHeaders(jsonHeaders),
  });
}

async function handleCreateUser(request: Request) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  const body = await parseJson<{ username?: string; display_name?: string; password?: string; role?: string; active?: boolean }>(request);
  const typedUsername = displayNameFromInput(body.username);
  const username = normalizeUsername(typedUsername);
  const displayName = displayNameFromInput(body.display_name) || typedUsername;
  const password = String(body.password ?? "");
  if (!username || !password) {
    return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const role = normalizeRole(body.role);
  const active = body.active === undefined ? true : Boolean(body.active);

  try {
    const user = await createUserWithActive(username, password, active, { role, displayName });
    audit(request, { event: "admin_user_create", success: true, userId: user.id, username: user.username, actorId: auth.id, detail: `role=${role} active=${active}` });
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
    display_name?: string;
    role?: string;
    active?: boolean;
    password?: string;
    scopes?: { calendar?: boolean; tracker?: boolean };
  }>(request);

  let user = await findUserById(id);
  if (!user) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }
  const previousUsername = user.username;

  const profileUpdate: { username?: string; displayName?: string; role?: UserRole; active?: boolean } = {};
  if (body.username !== undefined) profileUpdate.username = displayNameFromInput(body.username);
  if (body.display_name !== undefined) profileUpdate.displayName = displayNameFromInput(body.display_name);
  if (body.role !== undefined) profileUpdate.role = normalizeRole(body.role);
  if (body.active !== undefined) profileUpdate.active = Boolean(body.active);

  try {
    if (Object.keys(profileUpdate).length > 0) {
      const updated = await updateUserProfile(id, profileUpdate);
      if (updated) user = updated;
    }

    if (body.scopes !== undefined) {
      const scopes: UserScopes = { calendar: Boolean(body.scopes?.calendar), tracker: Boolean(body.scopes?.tracker) };
      const before = user.scopes;
      const updated = await updateUserScopes(id, scopes);
      if (updated) user = updated;
      // Losing an app signs the user out of the clients that cannot work without it.
      for (const app of APP_AUDIENCES) {
        if (before[app] && !scopes[app]) await oidc.endUserAppAccess(id, app);
      }
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

  if (!user.active) {
    await revokeAllRefreshTokensForUser(id);
  }
  if (!user.active || body.password) {
    await oidc.endUserSessions(id);
  }
  invalidateCachedUser(previousUsername);
  invalidateCachedUser(user.username);
  audit(request, {
    event: "admin_user_update",
    success: true,
    userId: user.id,
    username: user.username,
    actorId: auth.id,
    detail: describeUserUpdate(body),
  });

  return new Response(JSON.stringify(toPublicUser(user)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleDeleteUser(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;

  if (auth.id === id) {
    return new Response(JSON.stringify({ error: "You cannot delete your own account" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  const target = await findUserById(id);
  if (!target) {
    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  }

  // Before the row goes: the sessions are found through the user, and the apps still need telling.
  await oidc.endUserSessions(id);
  await deleteUserById(id);
  await deleteAvatar(id);
  invalidateCachedUser(target.username);
  // The row is gone, so the id is kept only in the detail.
  audit(request, { event: "admin_user_delete", success: true, username: target.username, actorId: auth.id, detail: id });

  return new Response(null, { status: 204, headers: withCorsHeaders({}) });
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
