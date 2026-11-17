import { z } from "@hono/zod-openapi";
import { config } from "./config.ts";
import { APP_AUDIENCES } from "./types.ts";

/**
 * Zod schemas shared by request validation and OpenAPI generation.
 *
 * A schema registered with `.openapi("Name")` becomes a `$ref` in
 * `components.schemas`, keeping the published document stable across the
 * hand-rolled → generated migration.
 */

const audienceDescription =
  "The app the session is for. The access token's `aud` is then just this app, and the request is refused when the user's scopes do not include it. Omitted, `aud` lists every app the user's scopes allow — unless the service runs with REQUIRE_AUDIENCE=true, in which case omitting it is a 400.";

// Fields are coerced/optional so the handlers keep their original validation
// messages and status codes; the OpenAPI metadata still documents the wire shape.
export const LoginRequest = z.object({
  username: z.coerce.string().optional().openapi({ example: "alice" }),
  password: z.coerce.string().optional().openapi({ example: "secret" }),
  audience: z.coerce.string().optional().openapi({ description: audienceDescription, enum: [...APP_AUDIENCES] }),
}).openapi("LoginRequest");

export const RefreshRequest = z.object({
  refresh_token: z.coerce.string().optional().openapi({ example: "eyJhbGciOi..." }),
}).openapi("RefreshRequest");

export const ChangePasswordRequest = z.object({
  current_password: z.coerce.string().optional().openapi({ example: "old-secret" }),
  new_password: z.coerce.string().optional().openapi({ example: "new-secret" }),
}).openapi("ChangePasswordRequest");

export const ChangePasswordResponse = z.object({
  success: z.boolean().openapi({ example: true }),
}).openapi("ChangePasswordResponse");

export const TokenResponse = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  expires_in: z.number().int().openapi({ example: config.accessTokenTtlSeconds }),
  refresh_expires_in: z.number().int().openapi({ example: config.refreshTokenTtlSeconds }),
}).openapi("TokenResponse");

export const LogoutResponse = z.object({
  success: z.boolean().openapi({ example: true }),
}).openapi("LogoutResponse");

export const UploadProfilePictureResponse = z.object({
  success: z.boolean().openapi({ example: true }),
  content_type: z.string().openapi({ example: "image/webp", enum: ["image/webp"] }),
}).openapi("UploadProfilePictureResponse");

export const OidcTokenRequest = z.object({
  grant_type: z.string().openapi({ enum: ["authorization_code", "refresh_token"] }),
  code: z.string().optional(),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
  refresh_token: z.string().optional(),
  client_id: z.string().optional().openapi({ description: "Public clients only; confidential clients authenticate with HTTP Basic." }),
}).openapi("OidcTokenRequest");

export const OidcClient = z.object({
  client_id: z.string().openapi({ example: "calendar-web" }),
  name: z.string(),
  is_public: z.boolean(),
  redirect_uris: z.array(z.string()),
  post_logout_redirect_uris: z.array(z.string()),
  backchannel_logout_uri: z.string().nullable(),
  allowed_scopes: z.array(z.string()),
  disabled: z.boolean(),
  has_secret: z.boolean(),
  previous_secret_expires_at: z.string().datetime().nullable().openapi({ description: "While set, the previous secret still works." }),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
}).openapi("OidcClient");

export const CreateOidcClientRequest = z.object({
  client_id: z.string().regex(/^[a-z0-9][a-z0-9._-]{1,62}$/),
  name: z.string(),
  is_public: z.boolean(),
  redirect_uris: z.array(z.string()).openapi({ description: "Matched exactly, except that a web URI also authorizes the same path and query on any subdomain of its host (for preview deployments). https, or http on localhost; a custom scheme only for a public client. No wildcards or fragments." }),
  post_logout_redirect_uris: z.array(z.string()).optional(),
  backchannel_logout_uri: z.string().nullable().optional().openapi({ description: "Confidential clients only; may not point at a private network in production." }),
  allowed_scopes: z.array(z.string()).openapi({ description: "Must include `openid`." }),
  disabled: z.boolean().optional(),
}).openapi("CreateOidcClientRequest");

export const UpdateOidcClientRequest = z.object({
  name: z.string().optional(),
  redirect_uris: z.array(z.string()).optional(),
  post_logout_redirect_uris: z.array(z.string()).optional(),
  backchannel_logout_uri: z.string().nullable().optional(),
  allowed_scopes: z.array(z.string()).optional(),
}).openapi("UpdateOidcClientRequest");

const AuditEvent = z.object({
  id: z.string(),
  event: z.string().openapi({ example: "login" }),
  success: z.boolean(),
  user_id: z.string().uuid().nullable(),
  username: z.string().nullable(),
  actor_id: z.string().uuid().nullable().openapi({ description: "The admin, for admin actions." }),
  ip: z.string().nullable(),
  user_agent: z.string().nullable(),
  detail: z.string().nullable(),
  created_at: z.string().datetime(),
});

export const AuditEventsResponse = z.object({
  items: z.array(AuditEvent),
  total: z.number().int(),
  page: z.number().int(),
  pageSize: z.number().int(),
  retention_days: z.number().int().openapi({ description: "0 means rows are kept forever." }),
}).openapi("AuditEventsResponse");

export const JwksResponse = z.object({
  keys: z.array(z.object({
    kty: z.string().openapi({ example: "EC" }),
    crv: z.string().openapi({ example: "P-256" }),
    x: z.string().openapi({ description: "Base64url-encoded x coordinate" }),
    y: z.string().openapi({ description: "Base64url-encoded y coordinate" }),
    use: z.string().openapi({ example: "sig" }),
    alg: z.string().openapi({ example: "ES256" }),
    kid: z.string().openapi({ description: "Key ID (RFC 7638 thumbprint)" }),
  })),
}).openapi("JwksResponse");

/** The empty body several endpoints accept (passkey login-options, rotate-secret, …). */
export const EmptyBody = z.object({}).passthrough();

/** Reusable error envelope, used by the validation hook. */
export const ErrorResponse = z.object({
  error: z.string(),
}).openapi("ErrorResponse");
