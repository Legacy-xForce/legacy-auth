import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { getConnInfo } from "hono/bun";
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
import { jsonHeaders } from "./http.ts";
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

// The client address is resolved once per request, in Hono middleware (or in the
// wrapper for OIDC paths, which bypass Hono). Handlers read it by Request below.
const ipCache = new WeakMap<Request, string | null>();

type AppEnv = { Variables: { user: UserRecord } };

// ---------------------------------------------------------------------------
// Validation error shape: keep the service's existing `{ "error": "..." }` envelope.
// ---------------------------------------------------------------------------
const defaultHook = (result: any, c: any) => {
  if (result.success) return undefined;
  return c.json({ error: "Invalid request" }, 400);
};

// ---------------------------------------------------------------------------
// Auth middleware. The handlers also call authenticate() defensively; a small
// WeakMap keeps that from hitting the database twice for the same request.
// ---------------------------------------------------------------------------
const authCache = new WeakMap<Request, UserRecord | Response>();

async function authenticate(request: Request): Promise<UserRecord | Response> {
  const cached = authCache.get(request);
  if (cached) return cached;
  const result = await resolveAuthentication(request);
  authCache.set(request, result);
  return result;
}

const requireAuth = async (c: any, next: any) => {
  const result = await authenticate(c.req.raw);
  if (result instanceof Response) return result;
  c.set("user", result);
  await next();
};

const requireAdmin = async (c: any, next: any) => {
  const result = await authenticate(c.req.raw);
  if (result instanceof Response) return result;
  if (result.role !== "admin") return unauthorized("Admin role required", 403);
  c.set("user", result);
  await next();
};

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------
function createApp() {
  const app = new OpenAPIHono<AppEnv>({ defaultHook });

  // Resolve the peer address from Bun's server (Hono's `env`) and remember it
  // for the handlers. This runs before every route and before validation.
  app.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env as PeerLookup);
    await next();
  });

  app.onError((error, c) => {
    console.error(error);
    const message = error instanceof Error ? error.message : "Internal server error";
    return c.json({ error: message }, 500);
  });

  // ---- routes whose bodies we validate with Zod ---------------------------
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
    (c) => handleLogin(c.req.raw, c.req.valid("json") as any),
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
    (c) => handleRefresh(c.req.raw, c.req.valid("json") as any),
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
    (c) => handleLogout(c.req.raw, c.req.valid("json") as any),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/auth/change-password", tags: ["Auth"],
      summary: "Change the authenticated user's password", security: [{ bearerAuth: [] }],
      middleware: [requireAuth],
      request: { body: { required: true, content: { "application/json": { schema: ChangePasswordRequest } } } },
      responses: {
        200: { description: "Password changed successfully", content: { "application/json": { schema: ChangePasswordResponse } } },
        400: { description: "Missing current_password or new_password" },
        401: { description: "Invalid access token or current password" },
        403: { description: "Account disabled" },
        429: { description: "Too many failed attempts; see the Retry-After header" },
      },
    }),
    (c) => handleChangePassword(c.req.raw, c.req.valid("json") as any),
  );

  app.openapi(
    createRoute({
      method: "get", path: "/auth/me", tags: ["Profile"],
      summary: "Read the authenticated user's own profile", security: [{ bearerAuth: [] }],
      middleware: [requireAuth],
      responses: {
        200: { description: "The user's public profile" },
        401: { description: "Unauthorized" },
      },
    }),
    (c) => handleGetMe(c.req.raw),
  );

  app.openapi(
    createRoute({
      method: "patch", path: "/auth/me", tags: ["Profile"],
      summary: "Update the authenticated user's own profile", security: [{ bearerAuth: [] }],
      middleware: [requireAuth],
      request: {
        body: {
          required: false,
          content: { "application/json": { schema: z.object({ username: z.string().optional(), display_name: z.string().optional() }) } },
        },
      },
      responses: { 200: { description: "The updated profile" }, 401: { description: "Unauthorized" } },
    }),
    (c) => handleUpdateMe(c.req.raw, c.req.valid("json") as any),
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
    () => {
      const statements = assetLinks();
      if (statements) return new Response(JSON.stringify(statements), { status: 200, headers: withCorsHeaders(jsonHeaders) });
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
    },
  );

  app.openapi(
    createRoute({
      method: "get", path: "/admin/users", tags: ["Admin"],
      summary: "List users", security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: {
        query: z.object({
          page: z.coerce.number().int().min(1).default(1),
          pageSize: z.coerce.number().int().min(1).transform((value) => Math.min(100, value)).default(20),
          q: z.string().optional(),
          role: z.string().optional(),
        }),
      },
      responses: { 200: { description: "A page of users" }, 401: { description: "Unauthorized" }, 403: { description: "Admin role required" } },
    }),
    (c) => handleListUsers(c.req.raw, new URL(c.req.url)),
  );

  app.openapi(
    createRoute({
      method: "post", path: "/admin/users", tags: ["Admin"],
      summary: "Create a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: {
        body: {
          required: true,
          content: { "application/json": { schema: z.object({
            username: z.string(), display_name: z.string().optional(), password: z.string(),
            role: z.string().optional(), active: z.boolean().optional(),
          }) } },
        },
      },
      responses: { 201: { description: "Created" }, 400: { description: "Invalid input" }, 403: { description: "Admin role required" }, 409: { description: "Username already exists" } },
    }),
    (c) => handleCreateUser(c.req.raw, c.req.valid("json") as any),
  );

  app.openapi(
    createRoute({
      method: "get", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Fetch a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: { params: z.object({ id: z.string() }) },
      responses: { 200: { description: "The user" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleGetUser(c.req.raw, c.req.param("id")),
  );

  app.openapi(
    createRoute({
      method: "patch", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Update a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: { params: z.object({ id: z.string() }) },
      responses: { 200: { description: "The updated user" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleUpdateUser(c.req.raw, c.req.param("id")),
  );

  app.openapi(
    createRoute({
      method: "delete", path: "/admin/users/{id}", tags: ["Admin"],
      summary: "Delete a user", security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: { params: z.object({ id: z.string() }) },
      responses: { 204: { description: "Deleted" }, 400: { description: "Cannot delete your own account" }, 403: { description: "Admin role required" }, 404: { description: "Not found" } },
    }),
    (c) => handleDeleteUser(c.req.raw, c.req.param("id")),
  );

  // Audit filters: validate shape, preserve the handler's exact field-name error text
  // and its clamping of out-of-range pageSize.
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
      security: [{ bearerAuth: [] }], middleware: [requireAdmin],
      request: { query: auditQuery },
      responses: {
        200: { description: "A page of audit events", content: { "application/json": { schema: AuditEventsResponse } } },
        400: { description: "A filter is malformed", content: { "application/json": { schema: ErrorResponse } } },
        401: { description: "Missing or invalid access token" },
        403: { description: "Admin role required" },
      },
    }),
    (c) => handleListAuditEvents(c.req.raw, new URL(c.req.url)),
    (result, c: any) => {
      if (result.success) return undefined;
      const field = String(result.error?.issues?.[0]?.path?.[0] ?? "filter");
      return c.json({ error: `Invalid ${field}` }, 400);
    },
  );

  // Component schemas used only by the documented-only operations in docs-overlay.ts
  // still need to be registered so their `$ref`s resolve.
  app.openAPIRegistry.register("OidcClient", OidcClient);
  app.openAPIRegistry.register("CreateOidcClientRequest", CreateOidcClientRequest);
  app.openAPIRegistry.register("UpdateOidcClientRequest", UpdateOidcClientRequest);
  app.openAPIRegistry.register("OidcTokenRequest", OidcTokenRequest);
  app.openAPIRegistry.register("UploadProfilePictureResponse", UploadProfilePictureResponse);

  // ---- passkey, profile picture and OIDC admin: real handlers, no schema
  // middleware so their exact validation errors and order are unchanged.
  app.post("/auth/passkey/login-options", (c) => handlePasskeyLoginOptions(c.req.raw));
  app.post("/auth/passkey/login-verify", (c) => handlePasskeyLoginVerify(c.req.raw));
  app.post("/auth/passkey/register-options", requireAuth, (c) => handlePasskeyRegisterOptions(c.req.raw, c.get("user")));
  app.post("/auth/passkey/register-verify", requireAuth, (c) => handlePasskeyRegisterVerify(c.req.raw, c.get("user")));
  app.get("/auth/passkey/credentials", requireAuth, (c) => handlePasskeyListCredentials(c.req.raw, c.get("user")));
  app.delete("/auth/passkey/credentials/:id", requireAuth, (c) => handlePasskeyDeleteCredential(c.req.raw, c.req.param("id"), c.get("user")));
  app.post("/auth/profile-picture", requireAuth, (c) => handleUploadProfilePicture(c.req.raw, c.get("user")));
  app.get("/auth/profile-picture/:userId", (c) => handleGetProfilePicture(c.req.raw, c.req.param("userId")));
  app.all("/admin/oidc/*", requireAdmin, async (c) => {
    const actor = c.get("user");
    const response = await handleOidcAdmin({ request: c.req.raw, url: new URL(c.req.url), actor, audit: (entry) => audit(c.req.raw, entry) });
    return response ?? new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  });
  app.post("/admin/users/:id/avatar", requireAdmin, (c) => handleUploadUserAvatar(c.req.raw, c.req.param("id"), c.get("user")));

  // ---- docs and the frontend catch-all
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
    return staticResponse ?? new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
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
 * Read the socket address with Hono's Bun adapter (`getConnInfo`) and apply the
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

function throttleIp(request: Request): string | null {
  const ip = clientIp(request);
  return ip && !isPrivateAddress(ip) ? ip : null;
}

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

async function parseJson<T>(request: Request): Promise<T> {
  return await request.json() as T;
}

async function handleLogin(request: Request, validatedBody?: { username?: string; password?: string; audience?: string }) {
  const body = validatedBody ?? await parseJson<{ username?: string; password?: string; audience?: string }>(request);
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

  const validPassword = await Bun.password.verify(password, user.password_hash);
  if (!validPassword) return reject("Invalid credentials", 401, user.id);
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
        id: updatedUser.id, username: updatedUser.username, display_name: updatedUser.display_name,
        password_hash: updatedUser.password_hash, role: updatedUser.role, active: updatedUser.active, scopes: updatedUser.scopes,
      };
      cacheUser(user);
    }
  }

  const accessToken = signAccessToken({ sub: user.id, username: user.username, displayName: user.display_name, role: user.role, scopes: user.scopes, audience });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username, app: body.audience ? audience[0] : undefined });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());
  audit(request, { event: "login", success: true, userId: user.id, username: user.username, detail: audience.join(",") || null });

  return new Response(JSON.stringify({
    access_token: accessToken, refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds, refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleRefresh(request: Request, validatedBody?: { refresh_token?: string }) {
  const body = validatedBody ?? await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });

  let payload;
  try { payload = verifyRefreshToken(rawToken); }
  catch { return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) }); }

  const stored = await findRefreshTokenByJti(payload.jti);
  if (!stored || (stored.revoked_at !== null && stored.rotated_at === null)) {
    audit(request, { event: "refresh", success: false, userId: stored?.user_id, username: payload.username, detail: "revoked or unknown token" });
    return new Response(JSON.stringify({ error: "Invalid or revoked refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (new Date(stored.expires_at).getTime() < Date.now()) {
    return new Response(JSON.stringify({ error: "Refresh token expired" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }
  if (!(await verifyRefreshTokenHash(rawToken, stored.token_hash))) {
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

  let audience;
  try { audience = resolveAudience(payload.app, user.scopes); }
  catch (error) {
    if (!(error instanceof AudienceError)) throw error;
    await revokeRefreshToken(payload.jti);
    audit(request, { event: "refresh", success: false, userId: user.id, username: user.username, detail: error.message });
    return new Response(JSON.stringify({ error: error.message }), { status: error.statusCode, headers: withCorsHeaders(jsonHeaders) });
  }

  const family = stored.family_id ?? stored.id;
  const claim = await claimRefreshToken(payload.jti, config.refreshReuseGraceSeconds);
  if (!claim) {
    const revoked = await revokeRefreshFamily(family);
    audit(request, {
      event: "refresh_reuse", success: false, userId: user.id, username: user.username,
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
    access_token: accessToken, refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds, refresh_expires_in: config.refreshTokenTtlSeconds,
  }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleLogout(request: Request, validatedBody?: { refresh_token?: string }) {
  const body = validatedBody ?? await parseJson<{ refresh_token?: string }>(request);
  const rawToken = String(body.refresh_token ?? "");
  if (!rawToken) return new Response(JSON.stringify({ error: "refresh_token is required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });

  let payload;
  try { payload = verifyRefreshToken(rawToken); }
  catch { return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) }); }

  await revokeRefreshToken(payload.jti);
  invalidateCachedUser(payload.username);
  return new Response(JSON.stringify({ success: true }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleChangePassword(request: Request, validatedBody?: { current_password?: string; new_password?: string }) {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) return new Response(JSON.stringify({ error: "Authorization bearer token is required" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });

  let payload;
  try { payload = verifyAccessToken(token); }
  catch { return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) }); }

  const body = validatedBody ?? await parseJson<{ current_password?: string; new_password?: string }>(request);
  const currentPassword = String(body.current_password ?? "");
  const newPassword = String(body.new_password ?? "");
  if (!currentPassword || !newPassword) {
    return new Response(JSON.stringify({ error: "current_password and new_password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }
  if (currentPassword === newPassword) {
    return new Response(JSON.stringify({ error: "new_password must be different from current_password" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }

  let user = await findUserById(payload.sub);
  if (!user) return new Response(JSON.stringify({ error: "Invalid access token" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
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
  if (!(await Bun.password.verify(currentPassword, user.password_hash))) {
    recordFailure(throttle);
    audit(request, { event: "password_change", success: false, userId: user.id, username: user.username, detail: "Current password is invalid" });
    return new Response(JSON.stringify({ error: "Current password is invalid" }), { status: 401, headers: withCorsHeaders(jsonHeaders) });
  }

  const newPasswordHash = await Bun.password.hash(newPassword);
  const updatedUser = await updateUserPasswordHash(user.id, newPasswordHash);
  if (!updatedUser) return new Response(JSON.stringify({ error: "Failed to update password" }), { status: 500, headers: withCorsHeaders(jsonHeaders) });

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
    return new Response(JSON.stringify({ error: error.message || "Passkey verification failed" }), { status, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handlePasskeyRegisterOptions(request: Request, _user?: UserRecord) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const options = await generateRegisterOptions(authResult);
  return new Response(JSON.stringify(options), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyRegisterVerify(request: Request, _user?: UserRecord) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const body = await parseJson<any>(request);
  try {
    const result = await verifyRegister(authResult.id, body);
    audit(request, { event: "passkey_register", success: true, userId: authResult.id, username: authResult.username, detail: result.credentialId });
    return new Response(JSON.stringify(result), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error: any) {
    const status = error.statusCode || 400;
    return new Response(JSON.stringify({ error: error.message || "Passkey registration failed" }), { status, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handlePasskeyListCredentials(request: Request, _user?: UserRecord) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  const list = await listCredentials(authResult.id);
  return new Response(JSON.stringify(list), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handlePasskeyDeleteCredential(request: Request, id: string, _user?: UserRecord) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  try {
    const result = await deleteCredential(id, authResult.id);
    audit(request, { event: "passkey_delete", success: true, userId: authResult.id, username: authResult.username, detail: id });
    return new Response(JSON.stringify(result), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error: any) {
    const status = error.statusCode || 400;
    return new Response(JSON.stringify({ error: error.message || "Failed to delete passkey" }), { status, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handleUploadProfilePicture(request: Request, _user?: UserRecord) {
  const authResult = await authenticate(request);
  if (authResult instanceof Response) return authResult;
  if (!authResult.active) return new Response(JSON.stringify({ error: "Account disabled" }), { status: 403, headers: withCorsHeaders(jsonHeaders) });
  return await performAvatarUpload(request, authResult.id);
}

async function performAvatarUpload(request: Request, userId: string): Promise<Response> {
  let formData: FormData;
  try { formData = await request.formData(); }
  catch { return new Response(JSON.stringify({ error: "Request must be multipart/form-data" }), { status: 400, headers: withCorsHeaders(jsonHeaders) }); }

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

async function handleGetProfilePicture(request: Request, userId: string) {
  if (!UUID_PATTERN.test(userId)) {
    return new Response(JSON.stringify({ error: "Invalid user id" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  }
  const avatar = await findAvatar(userId);
  if (!avatar) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  return await serveStaticFile(Bun.file(avatar.path), request, withCorsHeaders({
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

function unauthorized(message: string, status = 401) {
  return new Response(JSON.stringify({ error: message }), { status, headers: withCorsHeaders(jsonHeaders) });
}

async function resolveAuthentication(request: Request): Promise<UserRecord | Response> {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization") ?? "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length).trim() : "";
  if (!token) return unauthorized("Authorization bearer token is required");
  let payload;
  try { payload = verifyAccessToken(token); }
  catch { return unauthorized("Invalid access token"); }
  const user = await findUserById(payload.sub);
  if (!user) return unauthorized("Invalid access token");
  if (!user.active) return unauthorized("Account disabled", 403);
  return user;
}

async function authenticateAdmin(request: Request): Promise<UserRecord | Response> {
  const result = await authenticate(request);
  if (result instanceof Response) return result;
  if (result.role !== "admin") return unauthorized("Admin role required", 403);
  return result;
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

async function handleGetMe(request: Request) {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;
  return new Response(JSON.stringify(toPublicUser(auth)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUpdateMe(request: Request, validatedBody?: { username?: string; display_name?: string }) {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;
  const body = validatedBody ?? await parseJson<{ username?: string; display_name?: string }>(request);
  const update: { username?: string; displayName?: string } = {};
  if (body.username !== undefined) update.username = displayNameFromInput(body.username);
  if (body.display_name !== undefined) update.displayName = displayNameFromInput(body.display_name);
  if (Object.keys(update).length === 0) {
    return new Response(JSON.stringify(toPublicUser(auth)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  }
  try {
    const updated = await updateUserProfile(auth.id, update);
    if (!updated) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
    invalidateCachedUser(auth.username);
    invalidateCachedUser(updated.username);
    return new Response(JSON.stringify(toPublicUser(updated)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to update profile";
    if (message.toLowerCase().includes("unique")) return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
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
  return new Response(JSON.stringify({ items: items.map(toPublicUser), total, page, pageSize }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleListAuditEvents(request: Request, url: URL) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  const bad = (error: string) => new Response(JSON.stringify({ error }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  const params = url.searchParams;
  const page = Math.max(1, Math.trunc(Number(params.get("page") ?? "1")) || 1);
  const pageSize = Math.min(200, Math.max(1, Math.trunc(Number(params.get("pageSize") ?? "50")) || 50));
  const successParam = params.get("success");
  if (successParam !== null && successParam !== "true" && successParam !== "false") return bad("success must be true or false");
  const userId = params.get("userId");
  if (userId !== null && !UUID_PATTERN.test(userId)) return bad("userId must be a UUID");
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
    since: dates.since, until: dates.until, page, pageSize,
  });
  return new Response(JSON.stringify({ items, total, page, pageSize, retention_days: config.auditRetentionDays }), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleCreateUser(request: Request, validatedBody?: { username?: string; display_name?: string; password?: string; role?: string; active?: boolean }) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  const body = validatedBody ?? await parseJson<{ username?: string; display_name?: string; password?: string; role?: string; active?: boolean }>(request);
  const typedUsername = displayNameFromInput(body.username);
  const username = normalizeUsername(typedUsername);
  const displayName = displayNameFromInput(body.display_name) || typedUsername;
  const password = String(body.password ?? "");
  if (!username || !password) return new Response(JSON.stringify({ error: "username and password are required" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  const role = normalizeRole(body.role);
  const active = body.active === undefined ? true : Boolean(body.active);
  try {
    const user = await createUserWithActive(username, password, active, { role, displayName });
    audit(request, { event: "admin_user_create", success: true, userId: user.id, username: user.username, actorId: auth.id, detail: `role=${role} active=${active}` });
    return new Response(JSON.stringify(toPublicUser(user)), { status: 201, headers: withCorsHeaders(jsonHeaders) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to create user";
    if (message.toLowerCase().includes("unique")) return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
    return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }
}

async function handleGetUser(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  const user = await findUserById(id);
  if (!user) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  return new Response(JSON.stringify(toPublicUser(user)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleUpdateUser(request: Request, id: string, validatedBody?: any) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  const body: any = validatedBody ?? await parseJson<{
    username?: string; display_name?: string; role?: string; active?: boolean;
    password?: string; scopes?: { calendar?: boolean; tracker?: boolean };
  }>(request);
  let user = await findUserById(id);
  if (!user) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
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
    if (message.toLowerCase().includes("unique")) return new Response(JSON.stringify({ error: "Username already exists" }), { status: 409, headers: withCorsHeaders(jsonHeaders) });
    return new Response(JSON.stringify({ error: message }), { status: 500, headers: withCorsHeaders(jsonHeaders) });
  }
  if (!user.active) await revokeAllRefreshTokensForUser(id);
  if (!user.active || body.password) await oidc.endUserSessions(id);
  invalidateCachedUser(previousUsername);
  invalidateCachedUser(user.username);
  audit(request, {
    event: "admin_user_update", success: true, userId: user.id, username: user.username,
    actorId: auth.id, detail: describeUserUpdate(body),
  });
  return new Response(JSON.stringify(toPublicUser(user)), { status: 200, headers: withCorsHeaders(jsonHeaders) });
}

async function handleDeleteUser(request: Request, id: string) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  if (auth.id === id) return new Response(JSON.stringify({ error: "You cannot delete your own account" }), { status: 400, headers: withCorsHeaders(jsonHeaders) });
  const target = await findUserById(id);
  if (!target) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  await oidc.endUserSessions(id);
  await deleteUserById(id);
  await deleteAvatar(id);
  invalidateCachedUser(target.username);
  audit(request, { event: "admin_user_delete", success: true, username: target.username, actorId: auth.id, detail: id });
  return new Response(null, { status: 204, headers: withCorsHeaders({}) });
}

async function handleUploadUserAvatar(request: Request, id: string, _user?: UserRecord) {
  const auth = await authenticateAdmin(request);
  if (auth instanceof Response) return auth;
  const target = await findUserById(id);
  if (!target) return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: withCorsHeaders(jsonHeaders) });
  return await performAvatarUpload(request, target.id);
}
