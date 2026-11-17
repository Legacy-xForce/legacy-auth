import { createRoute, type OpenAPIHono } from "@hono/zod-openapi";
import { normalizeUsername } from "../usernames.ts";
import { throttleKeys, retryAfterSeconds, recordFailure } from "../throttle.ts";
import {
  generateLoginOptions, verifyLogin, generateRegisterOptions, verifyRegister,
  listCredentials, deleteCredential,
} from "../passkey.ts";
import { audit, tooManyAttempts } from "../lib/audit.ts";
import { throttleIp } from "../lib/client-ip.ts";
import { documentOnly } from "../lib/openapi.ts";
import { requireAuth } from "../middleware/auth.ts";
import type { AppEnv, Ctx } from "../lib/context.ts";

export function registerPasskeyRoutes(app: OpenAPIHono<AppEnv>) {
  documentOnly(app, createRoute({
    method: "post", path: "/auth/passkey/login-options", tags: ["Passkey"],
    summary: "Generate WebAuthn login options", deprecated: true,
    description: "Deprecated with `/auth/login`; passkeys are an authentication method at the OpenID Provider's sign-in page.",
    requestBody: { required: false, content: { "application/json": { schema: { type: "object", properties: { username: { type: "string" } } } } } },
    responses: { "200": { description: "WebAuthn assertion options" } },
  }), handleLoginOptions);

  documentOnly(app, createRoute({
    method: "post", path: "/auth/passkey/login-verify", tags: ["Passkey"],
    summary: "Verify WebAuthn assertion and issue tokens", deprecated: true,
    description: "Deprecated with `/auth/login`. Body is the WebAuthn assertion (`id`, `rawId`, `response`) plus an optional `audience`, as for `/auth/login`.",
    requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
    responses: {
      "200": { description: "Tokens issued successfully", content: { "application/json": { schema: { $ref: "#/components/schemas/TokenResponse" } } } },
      "400": { description: "Unknown audience" },
      "401": { description: "Invalid passkey signature or replay detected" },
      "403": { description: "Account disabled, or no access to the requested audience" },
      "429": { description: "Too many failed attempts; see the Retry-After header" },
    },
  }), handleLoginVerify);

  documentOnly(app, createRoute({
    method: "post", path: "/auth/passkey/register-options", tags: ["Passkey"],
    summary: "Generate WebAuthn registration options", security: [{ bearerAuth: [] }],
    responses: { "200": { description: "WebAuthn creation options" }, "401": { description: "Unauthorized" } },
  }), requireAuth as any, handleRegisterOptions);

  documentOnly(app, createRoute({
    method: "post", path: "/auth/passkey/register-verify", tags: ["Passkey"],
    summary: "Verify WebAuthn registration and store passkey credential", security: [{ bearerAuth: [] }],
    requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
    responses: {
      "200": { description: "Credential registered successfully" },
      "400": { description: "Invalid credential payload" },
      "401": { description: "Unauthorized" },
      "409": { description: "The credential id is registered to another account" },
    },
  }), requireAuth as any, handleRegisterVerify);

  documentOnly(app, createRoute({
    method: "get", path: "/auth/passkey/credentials", tags: ["Passkey"],
    summary: "List registered passkeys for current user", security: [{ bearerAuth: [] }],
    responses: { "200": { description: "List of registered passkeys" }, "401": { description: "Unauthorized" } },
  }), requireAuth as any, handleListCredentials);

  documentOnly(app, createRoute({
    method: "delete", path: "/auth/passkey/credentials/{id}", tags: ["Passkey"],
    summary: "Delete a registered passkey", security: [{ bearerAuth: [] }],
    parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
    responses: { "200": { description: "Passkey deleted" }, "401": { description: "Unauthorized" }, "404": { description: "Passkey not found" } },
  }), requireAuth as any, handleDeleteCredential);
}

async function handleLoginOptions(c: Ctx) {
  const parsed = await c.req.json().catch(() => ({}));
  const body: { username?: string } = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  const username = typeof body.username === "string" && body.username.trim() ? normalizeUsername(body.username) : undefined;
  return c.json(await generateLoginOptions(username) as any, 200);
}

async function handleLoginVerify(c: Ctx) {
  const parsed = await c.req.json().catch(() => ({}));
  const body = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
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

async function handleRegisterOptions(c: Ctx) {
  return c.json(await generateRegisterOptions(c.get("user")) as any, 200);
}

async function handleRegisterVerify(c: Ctx) {
  const user = c.get("user");
  const parsed = await c.req.json().catch(() => ({}));
  const body = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  try {
    const result = await verifyRegister(user.id, body);
    audit(c, { event: "passkey_register", success: true, userId: user.id, username: user.username, detail: result.credentialId });
    return c.json(result as any, 200);
  } catch (error: any) {
    return c.json({ error: error.message || "Passkey registration failed" } as any, error.statusCode || 400);
  }
}

async function handleListCredentials(c: Ctx) {
  return c.json(await listCredentials(c.get("user").id) as any, 200);
}

async function handleDeleteCredential(c: Ctx) {
  const user = c.get("user");
  const id = c.req.param("id")!;
  try {
    const result = await deleteCredential(id, user.id);
    audit(c, { event: "passkey_delete", success: true, userId: user.id, username: user.username, detail: id });
    return c.json(result as any, 200);
  } catch (error: any) {
    return c.json({ error: error.message || "Failed to delete passkey" } as any, error.statusCode || 400);
  }
}
