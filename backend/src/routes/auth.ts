import { createRoute, type OpenAPIHono } from "@hono/zod-openapi";
import { config } from "../config.ts";
import {
  findUserByUsername, findUserActiveByUsername, findUserById, saveRefreshToken,
  findRefreshTokenByJti, verifyRefreshTokenHash, claimRefreshToken, revokeRefreshFamily,
  revokeRefreshToken, revokeAllRefreshTokensForUser, updateUserPasswordHash,
} from "../db.ts";
import {
  signAccessToken, signRefreshToken, verifyRefreshToken, getRefreshTokenExpiresAt,
  resolveAudience, AudienceError,
} from "../jwt.ts";
import { getCachedUser, cacheUser, invalidateCachedUser } from "../cache.ts";
import { normalizeUsername } from "../usernames.ts";
import { throttleKeys, retryAfterSeconds, recordFailure, clearUserFailures } from "../throttle.ts";
import { oidc } from "../oidc/index.ts";
import { LoginRequest, RefreshRequest, ChangePasswordRequest, TokenResponse, LogoutResponse, ChangePasswordResponse, ErrorResponse } from "../schemas.ts";
import { audit, tooManyAttempts } from "../lib/audit.ts";
import { throttleIp } from "../lib/client-ip.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { AppEnv, JsonCtx } from "../lib/context.ts";

type LoginBody = { username: string; password: string; audience?: "calendar" | "tracker" };
type RefreshBody = { refresh_token: string };
type ChangePasswordBody = { current_password: string; new_password: string };

export function registerAuthRoutes(app: OpenAPIHono<AppEnv>) {
  app.openapi(
    createRoute({
      method: "post", path: "/auth/login", tags: ["Auth"],
      summary: "Authenticate a user and issue tokens", deprecated: true,
      description: "Deprecated: the Resource Owner Password Credentials grant. Use the OpenID Provider (`/.well-known/openid-configuration`). Still honours `audience`; every response carries `Deprecation: true`.",
      request: { body: { required: true, content: { "application/json": { schema: LoginRequest } } } },
      responses: {
        200: { description: "Tokens issued successfully", content: { "application/json": { schema: TokenResponse } } },
        400: { description: "Missing username or password, or unknown audience", content: { "application/json": { schema: ErrorResponse } } },
        401: { description: "Invalid credentials" },
        403: { description: "Account disabled, or no access to the requested audience" },
        429: { description: "Too many failed attempts; see the Retry-After header" },
      },
    }),
    (c) => handleLogin(c as JsonCtx<LoginBody>),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/auth/refresh", tags: ["Auth"],
      summary: "Exchange a refresh token for a new token pair",
      request: { body: { required: true, content: { "application/json": { schema: RefreshRequest } } } },
      responses: {
        200: { description: "Tokens refreshed successfully", content: { "application/json": { schema: TokenResponse } } },
        400: { description: "Missing refresh_token" },
        401: { description: "Invalid, revoked, or expired refresh token" },
        403: { description: "Account disabled, or no longer has access to the session's audience" },
      },
    }),
    (c) => handleRefresh(c as JsonCtx<RefreshBody>),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/auth/logout", tags: ["Auth"],
      summary: "Revoke a refresh token",
      request: { body: { required: true, content: { "application/json": { schema: RefreshRequest } } } },
      responses: {
        200: { description: "Refresh token revoked", content: { "application/json": { schema: LogoutResponse } } },
        400: { description: "Missing refresh_token" },
        401: { description: "Invalid refresh token" },
      },
    }),
    (c) => handleLogout(c as JsonCtx<RefreshBody>),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/auth/change-password", tags: ["Auth"],
      summary: "Change the authenticated user's password", security: [{ bearerAuth: [] }],
      middleware: [requireAuth as any],
      request: { body: { required: true, content: { "application/json": { schema: ChangePasswordRequest } } } },
      responses: {
        200: { description: "Password changed successfully", content: { "application/json": { schema: ChangePasswordResponse } } },
        400: { description: "Missing current_password or new_password" },
        401: { description: "Invalid access token or current password" },
        403: { description: "Account disabled" },
        429: { description: "Too many failed attempts; see the Retry-After header" },
      },
    }),
    (c) => handleChangePassword(c as JsonCtx<ChangePasswordBody>),
  );
}

async function handleLogin(c: JsonCtx<LoginBody>) {
  const { audience: requestedAudience } = c.req.valid("json");
  const username = normalizeUsername(c.req.valid("json").username);
  const password = c.req.valid("json").password;
  if (!username || !password) {
    return c.json({ error: "username and password are required" }, 400);
  }

  const throttle = throttleKeys(throttleIp(c), username);
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(c, { event: "login", success: false, username, detail: "throttled" });
    return tooManyAttempts(c, retryAfter);
  }
  const reject = (error: string, status: number, userId?: string) => {
    recordFailure(throttle);
    audit(c, { event: "login", success: false, userId, username, detail: error });
    return c.json({ error }, status as any);
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
    user = { ...user, active: status.active };
  } else {
    const record = await findUserByUsername(username);
    if (!record) return reject("Invalid credentials", 401);
    if (!record.active) return reject("Account disabled", 403, record.id);
    user = {
      id: record.id, username: record.username, display_name: record.display_name,
      password_hash: record.password_hash, role: record.role, active: record.active, scopes: record.scopes,
    };
    cacheUser(user);
  }

  if (!(await Bun.password.verify(password, user.password_hash))) return reject("Invalid credentials", 401, user.id);
  clearUserFailures(username);

  let audience;
  try {
    audience = resolveAudience(requestedAudience, user.scopes, { required: config.requireAudience });
  } catch (error) {
    if (!(error instanceof AudienceError)) throw error;
    audit(c, { event: "login", success: false, userId: user.id, username, detail: error.message });
    return c.json({ error: error.message }, error.statusCode);
  }

  if (user.password_hash.startsWith("$2")) {
    const upgradedPasswordHash = await Bun.password.hash(password);
    const updatedUser = await updateUserPasswordHash(user.id, upgradedPasswordHash);
    if (updatedUser) {
      user = {
        id: updatedUser.id, username: updatedUser.username, display_name: updatedUser.display_name,
        password_hash: updatedUser.password_hash, role: updatedUser.role, active: updatedUser.active, scopes: updatedUser.scopes,
      };
      cacheUser(user);
    }
  }

  const accessToken = signAccessToken({ sub: user.id, username: user.username, displayName: user.display_name, role: user.role, scopes: user.scopes, audience });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username, app: requestedAudience ? audience[0] : undefined });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());
  audit(c, { event: "login", success: true, userId: user.id, username: user.username, detail: audience.join(",") || null });

  return c.json({
    access_token: accessToken, refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds, refresh_expires_in: config.refreshTokenTtlSeconds,
  }, 200);
}

async function handleRefresh(c: JsonCtx<RefreshBody>) {
  const rawToken = c.req.valid("json").refresh_token;
  if (!rawToken) return c.json({ error: "refresh_token is required" }, 400);

  let payload;
  try { payload = verifyRefreshToken(rawToken); }
  catch { return c.json({ error: "Invalid refresh token" }, 401); }

  const stored = await findRefreshTokenByJti(payload.jti);
  if (!stored || (stored.revoked_at !== null && stored.rotated_at === null)) {
    audit(c, { event: "refresh", success: false, userId: stored?.user_id, username: payload.username, detail: "revoked or unknown token" });
    return c.json({ error: "Invalid or revoked refresh token" }, 401);
  }
  if (new Date(stored.expires_at).getTime() < Date.now()) return c.json({ error: "Refresh token expired" }, 401);
  if (!(await verifyRefreshTokenHash(rawToken, stored.token_hash))) return c.json({ error: "Invalid refresh token" }, 401);

  const user = await findUserById(payload.sub);
  if (!user) {
    await revokeRefreshToken(payload.jti);
    invalidateCachedUser(payload.username);
    return c.json({ error: "Invalid or revoked refresh token" }, 401);
  }
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(payload.username);
    return c.json({ error: "Account disabled" }, 403);
  }

  let audience;
  try { audience = resolveAudience(payload.app, user.scopes); }
  catch (error) {
    if (!(error instanceof AudienceError)) throw error;
    await revokeRefreshToken(payload.jti);
    audit(c, { event: "refresh", success: false, userId: user.id, username: user.username, detail: error.message });
    return c.json({ error: error.message }, error.statusCode);
  }

  const family = stored.family_id ?? stored.id;
  const claim = await claimRefreshToken(payload.jti, config.refreshReuseGraceSeconds);
  if (!claim) {
    const revoked = await revokeRefreshFamily(family);
    audit(c, {
      event: "refresh_reuse", success: false, userId: user.id, username: user.username,
      detail: `rotated token presented outside the grace period; ${revoked} token(s) of its family revoked`,
    });
    return c.json({ error: "Invalid or revoked refresh token" }, 401);
  }
  if (claim === "grace") {
    audit(c, { event: "refresh", success: true, userId: user.id, username: user.username, detail: "reused within grace period" });
  }
  const accessToken = signAccessToken({ sub: payload.sub, username: user.username, displayName: user.display_name, role: user.role, scopes: user.scopes, audience });
  const refreshTokenMeta = signRefreshToken({ sub: payload.sub, username: user.username, app: payload.app });
  await saveRefreshToken(payload.sub, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt(), family);

  return c.json({
    access_token: accessToken, refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds, refresh_expires_in: config.refreshTokenTtlSeconds,
  }, 200);
}

async function handleLogout(c: JsonCtx<RefreshBody>) {
  const rawToken = c.req.valid("json").refresh_token;
  if (!rawToken) return c.json({ error: "refresh_token is required" }, 400);

  let payload;
  try { payload = verifyRefreshToken(rawToken); }
  catch { return c.json({ error: "Invalid refresh token" }, 401); }

  await revokeRefreshToken(payload.jti);
  invalidateCachedUser(payload.username);
  return c.json({ success: true }, 200);
}

async function handleChangePassword(c: JsonCtx<ChangePasswordBody>) {
  const user = c.get("user");
  const { current_password: currentPassword, new_password: newPassword } = c.req.valid("json");
  if (!currentPassword || !newPassword) return c.json({ error: "current_password and new_password are required" }, 400);
  if (currentPassword === newPassword) return c.json({ error: "new_password must be different from current_password" }, 400);
  if (!user.active) {
    await revokeAllRefreshTokensForUser(user.id);
    invalidateCachedUser(user.username);
    return c.json({ error: "Account disabled" }, 403);
  }

  const throttle = throttleKeys(throttleIp(c), user.username);
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(c, { event: "password_change", success: false, userId: user.id, username: user.username, detail: "throttled" });
    return tooManyAttempts(c, retryAfter);
  }
  if (!(await Bun.password.verify(currentPassword, user.password_hash))) {
    recordFailure(throttle);
    audit(c, { event: "password_change", success: false, userId: user.id, username: user.username, detail: "Current password is invalid" });
    return c.json({ error: "Current password is invalid" }, 401);
  }

  const newPasswordHash = await Bun.password.hash(newPassword);
  const updatedUser = await updateUserPasswordHash(user.id, newPasswordHash);
  if (!updatedUser) return c.json({ error: "Failed to update password" }, 500);

  await revokeAllRefreshTokensForUser(updatedUser.id);
  await oidc.endUserSessions(updatedUser.id);
  invalidateCachedUser(updatedUser.username);
  audit(c, { event: "password_change", success: true, userId: updatedUser.id, username: updatedUser.username });
  return c.json({ success: true }, 200);
}
