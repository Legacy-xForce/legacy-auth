import { createRoute, z, type OpenAPIHono } from "@hono/zod-openapi";
import { updateUserProfile } from "../db.ts";
import { displayNameFromInput } from "../usernames.ts";
import { invalidateCachedUser } from "../cache.ts";
import { findAvatar, UUID_PATTERN } from "../avatars.ts";
import { serveStaticFile } from "../static.ts";
import { withCorsHeaders } from "../cors.ts";
import { UploadProfilePictureResponse } from "../schemas.ts";
import { documentOnly } from "../lib/openapi.ts";
import { performAvatarUpload } from "../lib/avatar-upload.ts";
import { userWriteErrorResponse } from "../lib/errors.ts";
import { toPublicUser } from "../lib/public-user.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { AppEnv, Ctx, JsonCtx } from "../lib/context.ts";

type ProfileBody = { username?: string; display_name?: string };

export function registerProfileRoutes(app: OpenAPIHono<AppEnv>) {
  app.openAPIRegistry.register("UploadProfilePictureResponse", UploadProfilePictureResponse);

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

  // The avatar endpoints keep their exact multipart/image validation in the handler.
  documentOnly(app, createRoute({
    method: "post", path: "/auth/profile-picture", tags: ["Profile"],
    summary: "Upload the authenticated user's profile picture",
    description: "Accepts JPEG, PNG, WebP, AVIF, or GIF images. Every image is resized to 256x256 (cropped to fit) and re-encoded as WebP. Animated input stays animated; transparency is preserved.",
    security: [{ bearerAuth: [] }],
    requestBody: {
      required: true,
      content: { "multipart/form-data": { schema: { type: "object", required: ["file"], properties: { file: { type: "string", format: "binary" } } } } },
    },
    responses: {
      "200": { description: "Profile picture stored successfully", content: { "application/json": { schema: UploadProfilePictureResponse } } },
      "400": { description: "Missing file, unsupported format, or corrupted image" },
      "401": { description: "Invalid access token" },
      "403": { description: "Account disabled" },
      "413": { description: "File exceeds maximum upload size" },
    },
  }), requireAuth as any, handleUploadProfilePicture);

  documentOnly(app, createRoute({
    method: "get", path: "/auth/profile-picture/{userId}", tags: ["Profile"],
    summary: "Fetch a user's profile picture",
    parameters: [{ name: "userId", in: "path", required: true, schema: { type: "string", format: "uuid" } }],
    responses: {
      "200": {
        description: "Profile picture image bytes (image/webp, or a legacy image/avif, image/jpeg, image/gif)",
        headers: { ETag: { description: "Validator for the stored file; send it back in If-None-Match to revalidate", schema: { type: "string" } } },
        content: {
          "image/avif": { schema: { type: "string", format: "binary" } },
          "image/webp": { schema: { type: "string", format: "binary" } },
          "image/jpeg": { schema: { type: "string", format: "binary" } },
          "image/gif": { schema: { type: "string", format: "binary" } },
        },
      },
      "304": { description: "Not Modified — the If-None-Match header matched the current ETag" },
      "400": { description: "Invalid user id" },
      "404": { description: "No profile picture stored for this user" },
    },
  }), handleGetProfilePicture);
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
    return userWriteErrorResponse(c, error, "Failed to update profile");
  }
}

async function handleUploadProfilePicture(c: Ctx) {
  const user = c.get("user");
  if (!user.active) return c.json({ error: "Account disabled" } as any, 403);
  return performAvatarUpload(c, user.id);
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
