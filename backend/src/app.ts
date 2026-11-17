import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { getConnInfo } from "hono/bun";
import type { Context } from "hono";
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
import { applyDocOverlay } from "./docs-overlay.ts";
import {
  LoginRequest, RefreshRequest, ChangePasswordRequest, ChangePasswordResponse,
  TokenResponse, LogoutResponse, UploadProfilePictureResponse, OidcClient,
  CreateOidcClientRequest, UpdateOidcClientRequest, AuditEventsResponse, JwksResponse,
  OidcTokenRequest, ErrorResponse,
} from "./schemas.ts";
import { oidc } from "./oidc/index.ts";
import { handleOidcAdmin } from "./oidc/admin.ts";
import { saveAvatar, findAvatar, deleteAvatar, UnsupportedImageError, UUID_PATTERN } from "./avatars.ts";
import { serveStaticFile } from "./static.ts";
import {
  generateLoginOptions,
  verifyLogin,
  generateRegisterOptions,
  verifyRegister,
  listCredentials,
  deleteCredential,
} from "./passkey.ts";
import { join, normalize } from "path";

/** The Bun server passed as the second argument to `fetch`. */
export type PeerLookup = { requestIP(request: Request): { address: string } | null };

type AppEnv = { Variables: { user: UserRecord } };
type Ctx = Context<AppEnv>;
type JsonCtx<T> = Context<AppEnv, any, { in: { json: T }; out: { json: T } }>;
type QueryCtx<T> = Context<AppEnv, any, { in: { query: T }; out: { query: T } }>;
type ListUsersQuery = { page: number; pageSize: number; q?: string; role?: string };
type AuditQuery = { event?: string; success?: "true" | "false"; userId?: string; username?: string; since?: string; until?: string; page: number; pageSize: number };
type LoginBody = { username: string; password: string; audience?: "calendar" | "tracker" };
type RefreshBody = { refresh_token: string };
type ChangePasswordBody = { current_password: string; new_password: string };
type ProfileBody = { username?: string; display_name?: string };
type CreateUserBody = { username?: string; display_name?: string; password?: string; role?: string; active?: boolean };

// The client address is resolved once per request and cached by Request so the
// wrapper (OIDC paths) and the Hono handlers see the same value.
const ipCache = new WeakMap<Request, string | null>();

/** Entry point for `Bun.serve({ fetch: handleRequest })`. Bun passes the server as the 2nd argument. */
export async function handleRequest(request: Request, server: PeerLookup): Promise<Response> {
  resolveClientIp(request, server);
  const url = new URL(request.url);
  // The OP owns its own CORS and security headers; leave its responses untouched.
  if (oidc.handles(url.pathname)) return oidc.handle(request, clientIp(request));
  if (request.method === "OPTIONS") return applyCorsOrigin(request, createCorsPreflightResponse(request));

  // Pass the Bun server as Hono's environment so getConnInfo() can read the peer.
  const response = markDeprecated(request, await app.fetch(request, server));
  return applyCorsOrigin(request, response);
}

/**
 * Resolve the peer address with Hono's Bun adapter (`getConnInfo`) and apply the
 * TRUST_PROXY rules. Cached per Request so every handler sees the same address.
 */
function resolveClientIp(request: Request, server: PeerLookup): string | null {
  const cached = ipCache.get(request);
  if (cached !== undefined) return cached;

  let peer: string | null = null;
  try {
    // getConnInfo only reads `env` and `req.raw`, so a minimal context is enough
    // on the OIDC path which does not go through Hono's middleware.
    const info = getConnInfo({ env: server, req: { raw: request } } as any);
    peer = info.remote.address ?? null;
  } catch (error) {
    console.error("[conninfo] failed to read the client address", error);
  }

  // Forwarded headers are believed only from a proxy on a private address: a
  // client reaching the port directly could otherwise claim any IP.
  if (config.trustProxy && peer && isPrivateAddress(peer)) {
    const forwarded = (request.headers.get("x-forwarded-for") ?? "")
      .split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
    for (let i = forwarded.length - 1; i >= 0; i--) {
      if (!isPrivateAddress(forwarded[i])) {
        ipCache.set(request, forwarded[i]);
        return forwarded[i];
      }
    }
  }
  ipCache.set(request, peer);
  return peer;
}

function clientIp(request: Request): string | null {
  return ipCache.get(request) ?? null;
}

function throttleIp(c: Ctx): string | null {
  const ip = clientIp(c.req.raw);
  return ip && !isPrivateAddress(ip) ? ip : null;
}

function audit(c: Ctx, entry: Omit<AuthEvent, "ip" | "userAgent">) {
  insertAuthEvent({ ...entry, ip: clientIp(c.req.raw), userAgent: c.req.header("user-agent") ?? null }).catch((error) => {
    console.error("[audit] failed to record auth event", error);
  });
}

function tooManyAttempts(c: Ctx, retryAfter: number) {
  return c.json({ error: "Too many failed attempts, try again later" }, 429, { "Retry-After": String(retryAfter) });
}

// ---------------------------------------------------------------------------
// Auth guards: resolve the user once, attach it to the context, and let handlers
// read it with c.get("user").
// ---------------------------------------------------------------------------
const requireAuth = async (c: Ctx, next: () => Promise<void>) => {
  const token = bearerToken(c);
  if (!token) return c.json({ error: "Authorization bearer token is required" }, 401);
  let payload;
  try { payload = verifyAccessToken(token); }
  catch { return c.json({ error: "Invalid access token" }, 401); }
  const user = await findUserById(payload.sub);
  if (!user) return c.json({ error: "Invalid access token" }, 401);
  if (!user.active) return c.json({ error: "Account disabled" }, 403);
  c.set("user", user);
  await next();
};

const requireAdmin = async (c: Ctx, next: () => Promise<void>) => {
  const token = bearerToken(c);
  if (!token) return c.json({ error: "Authorization bearer token is required" }, 401);
  let payload;
  try { payload = verifyAccessToken(token); }
  catch { return c.json({ error: "Invalid access token" }, 401); }
  const user = await findUserById(payload.sub);
  if (!user) return c.json({ error: "Invalid access token" }, 401);
  if (!user.active) return c.json({ error: "Account disabled" }, 403);
  if (user.role !== "admin") return c.json({ error: "Admin role required" }, 403);
  c.set("user", user);
  await next();
};

function bearerToken(c: Ctx): string {
  const header = c.req.header("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------
function createApp() {
  const app = new OpenAPIHono<AppEnv>({
    defaultHook: (result: any, c: any) => {
      if (result.success) return undefined;
      return c.json({ error: "Invalid request" }, 400);
    },
  });

  app.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env as PeerLookup);
    await next();
  });

  app.onError((error, c) => {
    console.error(error);
    return c.json({ error: error instanceof Error ? error.message : "Internal server error" }, 500);
  });

  // ---- validated routes ---------------------------------------------------
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

  app.openapi(
    createRoute({
      method: "get", path: "/auth/me", tags: ["Profile"],
      summary: "Read the authenticated user's own profile", security: [{ bearerAuth: [] }],
      middleware: [requireAuth as any],
      responses: { 200: { description: "The user's public profile" }, 401: { description: "Unauthorized" } },
    }),
    (c) => handleGetMe(c as Ctx),
  );

  app.openapi(
    createRoute({
      method: "patch", path: "/auth/me", tags: ["Profile"],
      summary: "Update the authenticated user's own profile", security: [{ bearerAuth: [] }],
      middleware: [requireAuth as any],
      request: { body: { required: false, content: { "application/json": { schema: z.object({ username: z.string().optional(), display_name: z.string().optional() }) } } } },
      responses: { 200: { description: "The updated profile" }, 401: { description: "Unauthorized" } },
    }),
    (c) => handleUpdateMe(c as JsonCtx<ProfileBody>),
  );

  app.openapi(
    createRoute({
      method: "get", path: "/.well-known/jwks.json", tags: ["Keys"],
      summary: "JSON Web Key Set",
      description: "Returns the public keys used to verify access token signatures (ES256). Consumers can use this endpoint to validate JWTs without sharing any secret.",
      responses: { 200: { description: "JWKS document", content: { "application/json": { schema: JwksResponse } } } },
    }),
    (c) => c.json(getJwks() as any, 200),
  );

  app.openapi(
    createRoute({
      method: "get", path: "/.well-known/assetlinks.json", tags: ["Keys"],
      summary: "Digital Asset Links",
      description: "Lists the Android apps (package and signing certificate SHA-256) allowed to use this host's passkeys, from PASSKEY_ANDROID_APPS.",
      responses: { 200: { description: "Asset Links statements" }, 404: { description: "No Android apps configured" } },
    }),
    (c) => {
      const statements = assetLinks();
      return statements
        ? c.json(statements as any, 200)
        : c.json({ error: "Not found" } as any, 404);
    },
  );

  app.openapi(
    createRoute({
      method: "get", path: "/admin/users", tags: ["Admin"],
      summary: "List users", security: [{ bearerAuth: [] }], middleware: [requireAdmin as any],
      request: { query: z.object({
        page: z.coerce.number().int().min(1).default(1),
        pageSize: z.coerce.number().int().min(1).transform((value) => Math.min(100, value)).default(20),
        q: z.string().optional(),
        role: z.string().optional(),
      }) },
      responses: { 200: { description: "A page of users" }, 401: { description: "Unauthorized" }, 403: { description: "Admin role required" } },
    }),
    (c) => handleListUsers(c as QueryCtx<ListUsersQuery>),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/admin/users", tags: ["Admin"],
      summary: "Create a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin as any],
      request: { body: { required: true, content: { "application/json": { schema: z.object({
        username: z.string(), display_name: z.string().optional(), password: z.string(),
        role: z.string().optional(), active: z.boolean().optional(),
      }) } } } },
      responses: { 201: { description: "Created" }, 400: { description: "Invalid input" }, 403: { description: "Admin role required" }, 409: { description: "Username already exists" } },
    }),
    (c) => handleCreateUser(c as JsonCtx<CreateUserBody>),
  );

  const paramId = { params: z.object({ id: z.string() }) } as const;
  app.openapi(
    createRoute({
      method: "get", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Fetch a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin as any], request: paramId,
      responses: { 200: { description: "The user" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleGetUser(c as Ctx),
  );

  app.openapi(
    createRoute({
      method: "patch", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Update a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin as any], request: paramId,
      responses: { 200: { description: "The updated user" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleUpdateUser(c as Ctx),
  );

  app.openapi(
    createRoute({
      method: "delete", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Delete a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin as any], request: paramId,
      responses: { 204: { description: "Deleted" }, 400: { description: "Cannot delete your own account" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleDeleteUser(c as Ctx),
  );

  const auditQuery = z.object({
    event: z.string().optional(),
    success: z.enum(["true", "false"]).optional(),
    userId: z.string().uuid().optional(),
    username: z.string().optional(),
    since: z.string().datetime().optional(),
    until: z.string().datetime().optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).transform((value) => Math.min(200, value)).default(50),
  });
  app.openapi(
    createRoute({
      method: "get", path: "/admin/audit-events", tags: ["Admin"],
      summary: "List audit events",
      description: `Sign-ins, refreshes, password and passkey changes and admin changes, newest first. Rows older than the retention period (AUDIT_RETENTION_DAYS, currently ${config.auditRetentionDays} days; 0 keeps everything) are pruned daily. Admin only.`,
      security: [{ bearerAuth: [] }], middleware: [requireAdmin as any],
      request: { query: auditQuery },
      responses: {
        200: { description: "A page of audit events", content: { "application/json": { schema: AuditEventsResponse } } },
        400: { description: "A filter is malformed", content: { "application/json": { schema: ErrorResponse } } },
        401: { description: "Missing or invalid access token" },
        403: { description: "Admin role required" },
      },
    }),
    (c) => handleListAuditEvents(c as QueryCtx<AuditQuery>),
    (result, c: any) => {
      if (result.success) return undefined;
      const field = String(result.error?.issues?.[0]?.path?.[0] ?? "filter");
      return c.json({ error: `Invalid ${field}` }, 400);
    },
  );

  // Components referenced only by the documented-only operations in docs-overlay.ts.
  app.openAPIRegistry.register("OidcClient", OidcClient);
  app.openAPIRegistry.register("CreateOidcClientRequest", CreateOidcClientRequest);
  app.openAPIRegistry.register("UpdateOidcClientRequest", UpdateOidcClientRequest);
  app.openAPIRegistry.register("OidcTokenRequest", OidcTokenRequest);
  app.openAPIRegistry.register("UploadProfilePictureResponse", UploadProfilePictureResponse);

  // ---- documented-only routes: validation and exact errors stay in the handler
  app.post("/auth/passkey/login-options", (c) => handlePasskeyLoginOptions(c));
  app.post("/auth/passkey/login-verify", (c) => handlePasskeyLoginVerify(c));
  app.post("/auth/passkey/register-options", requireAuth as any, (c) => handlePasskeyRegisterOptions(c as Ctx));
  app.post("/auth/passkey/register-verify", requireAuth as any, (c) => handlePasskeyRegisterVerify(c as Ctx));
  app.get("/auth/passkey/credentials", requireAuth as any, (c) => handlePasskeyListCredentials(c as Ctx));
  app.delete("/auth/passkey/credentials/:id", requireAuth as any, (c) => handlePasskeyDeleteCredential(c as Ctx));
  app.post("/auth/profile-picture", requireAuth as any, (c) => handleUploadProfilePicture(c as Ctx));
  app.get("/auth/profile-picture/:userId", (c) => handleGetProfilePicture(c as Ctx));
  app.all("/admin/oidc/*", requireAdmin as any, async (c) => {
    const actor = (c as Ctx).get("user");
    const response = await handleOidcAdmin({
      request: c.req.raw, url: new URL(c.req.url), actor,
      audit: (entry) => audit(c as Ctx, entry),
    });
    return response ?? c.json({ error: "Not found" } as any, 404);
  });
  app.post("/admin/users/:id/avatar", requireAdmin as any, (c) => handleUploadUserAvatar(c as Ctx));

  // ---- docs and frontend
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/openapi.json", (c) => {
    const generated = app.getOpenAPIDocument({
      openapi: "3.0.3",
      info: { title: "Legacy Auth Service", version: "0.1.0", description: "Authentication service for the Legacy ecosystem." },
      servers: [{ url: "/" }],
    });
    return c.json(applyDocOverlay(generated as any));
  });
  // Pin the Scalar bundle version so a CDN release cannot change the docs page.
  app.get("/docs", Scalar({
    url: "/openapi.json",
    pageTitle: "Legacy Auth API Docs",
    cdn: "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.80.0",
  }));
  app.get("*", async (c) => {
    const staticResponse = await tryServeFrontend(new URL(c.req.url).pathname, c.req.raw);
    return staticResponse ?? c.json({ error: "Not found" } as any, 404);
  });

  return app;
}

const app = createApp();

const DEPRECATED_LOGIN_ENDPOINTS = new Set(["POST /auth/login", "POST /auth/passkey/login-options", "POST /auth/passkey/login-verify"]);

function markDeprecated(request: Request, response: Response): Response {
  if (DEPRECATED_LOGIN_ENDPOINTS.has(`${request.method} ${new URL(request.url).pathname}`)) {
    response.headers.set("Deprecation", "true");
    response.headers.set("Link", `<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  }
  return response;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
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

async function handlePasskeyLoginOptions(c: Ctx) {
  const body = await c.req.json<{ username?: string }>().catch(() => ({}) as { username?: string });
  const username = typeof body.username === "string" && body.username.trim() ? normalizeUsername(body.username) : undefined;
  return c.json(await generateLoginOptions(username) as any, 200);
}

async function handlePasskeyLoginVerify(c: Ctx) {
  const body = await c.req.json().catch(() => ({}));
  const throttle = throttleKeys(throttleIp(c));
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) {
    audit(c, { event: "passkey_login", success: false, detail: "throttled" });
    return tooManyAttempts(c, retryAfter);
  }
  try {
    const result = await verifyLogin(body);
    audit(c, { event: "passkey_login", success: true, userId: result.user.id, username: result.user.username });
    return c.json(result as any, 200);
  } catch (error: any) {
    const status = error.statusCode || 401;
    if (status === 401) recordFailure(throttle);
    audit(c, { event: "passkey_login", success: false, detail: error.message || "Passkey verification failed" });
    return c.json({ error: error.message || "Passkey verification failed" } as any, status);
  }
}

async function handlePasskeyRegisterOptions(c: Ctx) {
  return c.json(await generateRegisterOptions(c.get("user")) as any, 200);
}

async function handlePasskeyRegisterVerify(c: Ctx) {
  const user = c.get("user");
  const body = await c.req.json().catch(() => ({}));
  try {
    const result = await verifyRegister(user.id, body);
    audit(c, { event: "passkey_register", success: true, userId: user.id, username: user.username, detail: result.credentialId });
    return c.json(result as any, 200);
  } catch (error: any) {
    return c.json({ error: error.message || "Passkey registration failed" } as any, error.statusCode || 400);
  }
}

async function handlePasskeyListCredentials(c: Ctx) {
  return c.json(await listCredentials(c.get("user").id) as any, 200);
}

async function handlePasskeyDeleteCredential(c: Ctx) {
  const user = c.get("user");
  try {
    const result = await deleteCredential(c.req.param("id")!, user.id);
    audit(c, { event: "passkey_delete", success: true, userId: user.id, username: user.username, detail: c.req.param("id")! });
    return c.json(result as any, 200);
  } catch (error: any) {
    return c.json({ error: error.message || "Failed to delete passkey" } as any, error.statusCode || 400);
  }
}

async function handleUploadProfilePicture(c: Ctx) {
  const user = c.get("user");
  if (!user.active) return c.json({ error: "Account disabled" } as any, 403);
  return performAvatarUpload(c, user.id);
}

async function performAvatarUpload(c: Ctx, userId: string) {
  let formData: FormData;
  try { formData = await c.req.formData(); }
  catch { return c.json({ error: "Request must be multipart/form-data" } as any, 400); }

  const file = formData.get("file");
  if (!(file instanceof Blob) || file.size === 0) return c.json({ error: "file is required" } as any, 400);
  if (file.size > config.avatarMaxUploadBytes) {
    return c.json({ error: `file exceeds maximum size of ${config.avatarMaxUploadBytes} bytes` } as any, 413);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    const saved = await saveAvatar(userId, bytes);
    return c.json({ success: true, content_type: saved.contentType } as any, 200);
  } catch (error) {
    if (error instanceof UnsupportedImageError) return c.json({ error: error.message } as any, 400);
    return c.json({ error: "Invalid or corrupted image" } as any, 400);
  }
}

async function handleGetProfilePicture(c: Ctx) {
  const userId = c.req.param("userId")!;
  if (!UUID_PATTERN.test(userId)) return c.json({ error: "Invalid user id" } as any, 400);
  const avatar = await findAvatar(userId);
  if (!avatar) return c.json({ error: "Not found" } as any, 404);
  return await serveStaticFile(Bun.file(avatar.path), c.req.raw, withCorsHeaders({
    "Content-Type": avatar.contentType,
    "Cache-Control": "public, max-age=300",
  }));
}

async function tryServeFrontend(pathname: string, request: Request): Promise<Response | null> {
  const decoded = decodeURIComponent(pathname);
  const relative = normalize(decoded).replace(/^(\.\.[/\\])+/, "").replace(/^\/+/, "");
  const candidate = join(config.frontendDistDir, relative || "index.html");
  const file = Bun.file(candidate);
  if (await file.exists()) return await serveStaticFile(file, request);
  const indexFile = Bun.file(join(config.frontendDistDir, "index.html"));
  if (await indexFile.exists()) return await serveStaticFile(indexFile, request);
  return null;
}

function toPublicUser(user: UserRecord) {
  return {
    id: user.id, username: user.username, display_name: user.display_name,
    role: user.role, active: user.active, scopes: user.scopes,
    created_at: user.created_at, updated_at: user.updated_at,
  };
}

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

async function handleGetMe(c: Ctx) {
  return c.json(toPublicUser(c.get("user")) as any, 200);
}

async function handleUpdateMe(c: JsonCtx<ProfileBody>) {
  const current = c.get("user");
  const body = c.req.valid("json");
  const update: { username?: string; displayName?: string } = {};
  if (body.username !== undefined) update.username = displayNameFromInput(body.username);
  if (body.display_name !== undefined) update.displayName = displayNameFromInput(body.display_name);
  if (Object.keys(update).length === 0) return c.json(toPublicUser(current) as any, 200);

  try {
    const updated = await updateUserProfile(current.id, update);
    if (!updated) return c.json({ error: "Not found" } as any, 404);
    invalidateCachedUser(current.username);
    invalidateCachedUser(updated.username);
    return c.json(toPublicUser(updated) as any, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to update profile";
    if (message.toLowerCase().includes("unique")) return c.json({ error: "Username already exists" } as any, 409);
    return c.json({ error: message } as any, 500);
  }
}

async function handleListUsers(c: QueryCtx<ListUsersQuery>) {
  const page = c.req.valid("query").page;
  const pageSize = c.req.valid("query").pageSize;
  const search = c.req.valid("query").q?.trim() || undefined;
  const roleParam = c.req.valid("query").role;
  const role = roleParam === "admin" || roleParam === "user" ? roleParam : undefined;
  const { items, total } = await listUsersPaginated({ search, role, page, pageSize });
  return c.json({ items: items.map(toPublicUser), total, page, pageSize } as any, 200);
}

async function handleListAuditEvents(c: QueryCtx<AuditQuery>) {
  const params = c.req.valid("query");
  const { items, total } = await listAuthEvents({
    event: params.event,
    success: params.success === undefined ? undefined : params.success === "true",
    userId: params.userId,
    username: params.username?.trim() || undefined,
    since: params.since ? new Date(params.since) : undefined,
    until: params.until ? new Date(params.until) : undefined,
    page: params.page,
    pageSize: params.pageSize,
  });
  return c.json({ items, total, page: params.page, pageSize: params.pageSize, retention_days: config.auditRetentionDays } as any, 200);
}

async function handleCreateUser(c: JsonCtx<CreateUserBody>) {
  const actor = c.get("user");
  const body = c.req.valid("json");
  const typedUsername = displayNameFromInput(body.username);
  const username = normalizeUsername(typedUsername);
  const displayName = displayNameFromInput(body.display_name) || typedUsername;
  const password = String(body.password ?? "");
  if (!username || !password) return c.json({ error: "username and password are required" } as any, 400);
  const role = normalizeRole(body.role);
  const active = body.active === undefined ? true : Boolean(body.active);
  try {
    const user = await createUserWithActive(username, password, active, { role, displayName });
    audit(c, { event: "admin_user_create", success: true, userId: user.id, username: user.username, actorId: actor.id, detail: `role=${role} active=${active}` });
    return c.json(toPublicUser(user) as any, 201);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to create user";
    if (message.toLowerCase().includes("unique")) return c.json({ error: "Username already exists" } as any, 409);
    return c.json({ error: message } as any, 500);
  }
}

async function handleGetUser(c: Ctx) {
  const user = await findUserById(c.req.param("id")!);
  if (!user) return c.json({ error: "Not found" } as any, 404);
  return c.json(toPublicUser(user) as any, 200);
}

async function handleUpdateUser(c: Ctx) {
  const actor = c.get("user");
  const id = c.req.param("id")!;
  const body = await c.req.json<any>().catch(() => ({}));
  let user = await findUserById(id);
  if (!user) return c.json({ error: "Not found" } as any, 404);
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
    if (message.toLowerCase().includes("unique")) return c.json({ error: "Username already exists" } as any, 409);
    return c.json({ error: message } as any, 500);
  }
  if (!user.active) await revokeAllRefreshTokensForUser(id);
  if (!user.active || body.password) await oidc.endUserSessions(id);
  invalidateCachedUser(previousUsername);
  invalidateCachedUser(user.username);
  audit(c, { event: "admin_user_update", success: true, userId: user.id, username: user.username, actorId: actor.id, detail: describeUserUpdate(body) });
  return c.json(toPublicUser(user) as any, 200);
}

async function handleDeleteUser(c: Ctx) {
  const actor = c.get("user");
  const id = c.req.param("id")!;
  if (actor.id === id) return c.json({ error: "You cannot delete your own account" } as any, 400);
  const target = await findUserById(id);
  if (!target) return c.json({ error: "Not found" } as any, 404);
  await oidc.endUserSessions(id);
  await deleteUserById(id);
  await deleteAvatar(id);
  invalidateCachedUser(target.username);
  audit(c, { event: "admin_user_delete", success: true, username: target.username, actorId: actor.id, detail: id });
  return c.body(null, 204);
}

async function handleUploadUserAvatar(c: Ctx) {
  const target = await findUserById(c.req.param("id")!);
  if (!target) return c.json({ error: "Not found" } as any, 404);
  return performAvatarUpload(c, target.id);
}
