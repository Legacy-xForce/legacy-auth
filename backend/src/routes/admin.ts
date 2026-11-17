import { createRoute, z, type OpenAPIHono } from "@hono/zod-openapi";
import { config } from "../config.ts";
import {
  listUsersPaginated, createUserWithActive, findUserById, updateUserProfile,
  updateUserScopes, updateUserPasswordHash, revokeAllRefreshTokensForUser,
  deleteUserById, listAuthEvents,
} from "../db.ts";
import { displayNameFromInput, normalizeUsername } from "../usernames.ts";
import { invalidateCachedUser } from "../cache.ts";
import { oidc } from "../oidc/index.ts";
import { saveAvatar, deleteAvatar, UnsupportedImageError } from "../avatars.ts";
import { APP_AUDIENCES, type UserRole, type UserScopes, type UserRecord } from "../types.ts";
import { AuditEventsResponse, ErrorResponse } from "../schemas.ts";
import { audit } from "../lib/audit.ts";
import { documentOnly } from "../lib/openapi.ts";
import { requireAdmin } from "../middleware/auth.ts";
import type { AppEnv, Ctx, JsonCtx, QueryCtx } from "../lib/context.ts";

type CreateUserBody = { username?: string; display_name?: string; password?: string; role?: string; active?: boolean };
type ListUsersQuery = { page: number; pageSize: number; q?: string; role?: string };
type AuditQuery = { event?: string; success?: "true" | "false"; userId?: string; username?: string; since?: string; until?: string; page: number; pageSize: number };

export function registerAdminRoutes(app: OpenAPIHono<AppEnv>) {
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

  documentOnly(app, createRoute({
    method: "post", path: "/admin/users/{id}/avatar", tags: ["Admin"],
    summary: "Upload a user's profile picture on their behalf",
    security: [{ bearerAuth: [] }],
    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
    requestBody: { required: true, content: { "multipart/form-data": { schema: { type: "object", required: ["file"], properties: { file: { type: "string", format: "binary" } } } } } },
    responses: { "200": { description: "Profile picture stored" }, "400": { description: "Invalid image" }, "403": { description: "Admin role required" }, "404": { description: "Unknown user" } },
  }), requireAdmin as any, handleUploadUserAvatar);
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
