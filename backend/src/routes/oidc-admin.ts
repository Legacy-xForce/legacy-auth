import { createRoute, type OpenAPIHono } from "@hono/zod-openapi";
import { createOidcAdminRouter } from "../oidc/admin.ts";
import { OidcClient, CreateOidcClientRequest, UpdateOidcClientRequest, OidcTokenRequest } from "../schemas.ts";
import { documentSchema } from "../lib/openapi.ts";
import { requireAdmin } from "../middleware/auth.ts";
import type { AppEnv } from "../lib/context.ts";

const clientIdParam: Array<{ name: string; in: "path"; required: boolean; schema: { type: "string" } }> = [
  { name: "clientId", in: "path", required: true, schema: { type: "string" } },
];
const security = [{ bearerAuth: [] }];

export function registerOidcAdminRoutes(app: OpenAPIHono<AppEnv>) {
  app.openAPIRegistry.register("OidcClient", OidcClient);
  app.openAPIRegistry.register("CreateOidcClientRequest", CreateOidcClientRequest);
  app.openAPIRegistry.register("UpdateOidcClientRequest", UpdateOidcClientRequest);
  // Referenced by the OIDC discovery overlay, not by a Zod route.
  app.openAPIRegistry.register("OidcTokenRequest", OidcTokenRequest);

  documentSchema(app, createRoute({
    method: "get", path: "/admin/oidc/clients", tags: ["Admin"],
    summary: "List registered OpenID clients", security,
    responses: {
      "200": { description: "Clients, never with secret material", content: { "application/json": { schema: { type: "object", properties: { items: { type: "array", items: { $ref: "#/components/schemas/OidcClient" } } } } } } },
      "401": { description: "Missing or invalid access token" },
      "403": { description: "Admin role required" },
    },
  }));

  documentSchema(app, createRoute({
    method: "post", path: "/admin/oidc/clients", tags: ["Admin"],
    summary: "Register an OpenID client",
    description: "A confidential client gets a secret, returned once in `client_secret`; only its hash is stored.",
    security,
    requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/CreateOidcClientRequest" } } } },
    responses: {
      "201": { description: "Created", content: { "application/json": { schema: { type: "object", properties: { client: { $ref: "#/components/schemas/OidcClient" }, client_secret: { type: "string" } } } } } },
      "400": { description: "Invalid field (redirect URI rules, scopes, client_id, ...)" },
      "401": { description: "Missing or invalid access token" },
      "403": { description: "Admin role required" },
      "409": { description: "client_id already exists" },
    },
  }));

  documentSchema(app, createRoute({
    method: "get", path: "/admin/oidc/clients/{clientId}", tags: ["Admin"],
    summary: "Read one OpenID client", security, parameters: clientIdParam,
    responses: { "200": { description: "The client", content: { "application/json": { schema: { $ref: "#/components/schemas/OidcClient" } } } }, "404": { description: "Unknown client" } },
  }));

  documentSchema(app, createRoute({
    method: "patch", path: "/admin/oidc/clients/{clientId}", tags: ["Admin"],
    summary: "Update an OpenID client",
    description: "Any of `name`, `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_uri`, `allowed_scopes`. `is_public` cannot change; other fields are refused.",
    security, parameters: clientIdParam,
    requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/UpdateOidcClientRequest" } } } },
    responses: { "200": { description: "The updated client" }, "400": { description: "Invalid or unknown field" }, "404": { description: "Unknown client" } },
  }));

  documentSchema(app, createRoute({
    method: "post", path: "/admin/oidc/clients/{clientId}/rotate-secret", tags: ["Admin"],
    summary: "Issue a new client secret",
    description: "The new secret is returned once. The previous one keeps working for `grace_seconds` (default OIDC_SECRET_ROTATION_GRACE_SECONDS; 0 revokes it at once). Refresh tokens are unaffected.",
    security, parameters: clientIdParam,
    requestBody: { required: false, content: { "application/json": { schema: { type: "object", properties: { grace_seconds: { type: "number", minimum: 0, maximum: 2592000 } } } } } },
    responses: { "200": { description: "The client and its new `client_secret`" }, "400": { description: "A public client has no secret, or the grace period is out of range" }, "404": { description: "Unknown client" } },
  }));

  documentSchema(app, createRoute({
    method: "post", path: "/admin/oidc/clients/{clientId}/disable", tags: ["Admin"],
    summary: "Disable an OpenID client",
    description: "A disabled client gets `invalid_client` from every endpoint, refreshes included.",
    security, parameters: clientIdParam,
    responses: { "200": { description: "The client" }, "404": { description: "Unknown client" } },
  }));

  documentSchema(app, createRoute({
    method: "post", path: "/admin/oidc/clients/{clientId}/enable", tags: ["Admin"],
    summary: "Enable an OpenID client",
    description: "A confidential client needs a secret first (see rotate-secret).",
    security, parameters: clientIdParam,
    responses: { "200": { description: "The client" }, "404": { description: "Unknown client" }, "409": { description: "The client has no secret yet" } },
  }));

  // Scope the guard with Hono path patterns, not a pathname check: the bare
  // `/admin/oidc` stays a plain 404, and only registry routes need an admin.
  app.use("/admin/oidc/clients", requireAdmin as any);
  app.use("/admin/oidc/clients/*", requireAdmin as any);
  // Hono owns path and method dispatch inside the registry now; the handlers'
  // field validation and exact error messages are unchanged.
  app.route("/admin/oidc", createOidcAdminRouter() as any);
}
