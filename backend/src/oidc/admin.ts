import { Hono } from "hono";
import { withCorsHeaders } from "../cors.ts";
import { jsonHeaders } from "../http.ts";
import { audit } from "../lib/audit.ts";
import { readJsonObjectFromRequest } from "../lib/json.ts";
import type { AppEnv, Ctx } from "../lib/context.ts";
import {
  ClientExistsError,
  ClientValidationError,
  createClient,
  getClient,
  listClients,
  rotateClientSecret,
  setClientDisabled,
  toPublicClient,
  updateClient,
  validateClientFields,
  type ClientFields,
} from "./clients.ts";

const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const MAX_ROTATION_GRACE_SECONDS = 30 * 86400;

// Responses can carry a client secret, so none of them may be cached.
const noStore = () => Object.fromEntries(withCorsHeaders({ ...jsonHeaders, "cache-control": "no-store", pragma: "no-cache" }).entries());

const respond = (c: Ctx, status: 200 | 201 | 400 | 404 | 409, body: unknown) => c.json(body as any, status, noStore());
const notFound = (c: Ctx) => respond(c, 404, { error: "Client not found" });

const currentFields = (row: NonNullable<Awaited<ReturnType<typeof getClient>>>): ClientFields => ({
  name: row.name,
  is_public: row.is_public,
  redirect_uris: row.redirect_uris,
  post_logout_redirect_uris: row.post_logout_redirect_uris,
  backchannel_logout_uri: row.backchannel_logout_uri,
  allowed_scopes: row.allowed_scopes,
  primary_resource: row.primary_resource,
  default_resources: row.default_resources,
});

const EDITABLE = ["name", "redirect_uris", "post_logout_redirect_uris", "backchannel_logout_uri", "allowed_scopes", "primary_resource", "default_resources"];

/**
 * `/admin/oidc/clients…`: the registry of relying parties. Hono owns path and
 * method dispatch; the caller has already checked the admin role. Mounted under
 * `/admin/oidc` by routes/oidc-admin.ts.
 */
export function createOidcAdminRouter(): Hono<AppEnv> {
  const router = new Hono<AppEnv>();

  router.onError((error, c) => {
    if (error instanceof ClientValidationError) return respond(c, 400, { error: error.message });
    if (error instanceof ClientExistsError) return respond(c, 409, { error: error.message });
    throw error;
  });

  router.notFound((c) => respond(c, 404, { error: "Not found" }));

  // The old router's path regex refused malformed client ids with a 404. Hono's
  // `:clientId` matches any segment, so keep that check as a param middleware.
  const validClientId = async (c: Ctx, next: () => Promise<void>) => {
    if (!CLIENT_ID_PATTERN.test(c.req.param("clientId") ?? "")) return notFound(c);
    await next();
  };
  router.use("/clients/:clientId", validClientId);
  router.use("/clients/:clientId/*", validClientId);

  const record = (c: Ctx, event: string, clientId: string, detail?: string) => {
    const actor = c.get("user");
    audit(c, { event, success: true, userId: actor.id, username: actor.username, actorId: actor.id, detail: detail ? `${clientId}: ${detail}` : clientId });
  };

  router.get("/clients", async (c) => {
    return respond(c, 200, { items: (await listClients()).map(toPublicClient) });
  });

  router.post("/clients", async (c) => {
    const body = await readJsonObjectFromRequest(c.req.raw);
    if (!body) return respond(c, 400, { error: "A JSON object body is required" });
    const clientId = typeof body.client_id === "string" ? body.client_id : "";
    const fields = validateClientFields(body);
    const { client, secret } = await createClient(clientId, fields, { disabled: body.disabled === true });
    record(c, "admin_oidc_client_create", clientId, fields.is_public ? "public" : "confidential");
    return respond(c, 201, { client: toPublicClient(client), ...(secret ? { client_secret: secret } : {}) });
  });

  router.get("/clients/:clientId", async (c) => {
    const row = await getClient(c.req.param("clientId"));
    return row ? respond(c, 200, toPublicClient(row)) : notFound(c);
  });

  router.patch("/clients/:clientId", async (c) => {
    const clientId = c.req.param("clientId");
    const row = await getClient(clientId);
    if (!row) return notFound(c);
    const body = await readJsonObjectFromRequest(c.req.raw);
    if (!body) return respond(c, 400, { error: "A JSON object body is required" });
    if ("is_public" in body && body.is_public !== row.is_public) {
      return respond(c, 400, { error: "is_public cannot be changed; register a new client instead" });
    }
    const unknown = Object.keys(body).filter((key) => !EDITABLE.includes(key) && key !== "is_public");
    if (unknown.length > 0) return respond(c, 400, { error: `cannot update: ${unknown.join(", ")}` });
    const updated = await updateClient(clientId, validateClientFields(body, currentFields(row)));
    if (!updated) return notFound(c);
    record(c, "admin_oidc_client_update", clientId, Object.keys(body).join(","));
    return respond(c, 200, toPublicClient(updated));
  });

  router.post("/clients/:clientId/rotate-secret", async (c) => {
    const clientId = c.req.param("clientId");
    const body = (await readJsonObjectFromRequest(c.req.raw)) ?? {};
    let grace: number | undefined;
    if ("grace_seconds" in body) {
      const value = body.grace_seconds;
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > MAX_ROTATION_GRACE_SECONDS) {
        return respond(c, 400, { error: `grace_seconds must be between 0 and ${MAX_ROTATION_GRACE_SECONDS}` });
      }
      grace = value;
    }
    const row = await getClient(clientId);
    if (!row) return notFound(c);
    if (row.is_public) return respond(c, 400, { error: "A public client has no secret" });
    const rotated = await rotateClientSecret(clientId, grace);
    if (!rotated) return notFound(c);
    record(c, "admin_oidc_client_rotate_secret", clientId, `previous secret valid for ${grace ?? "the default grace period"}s`);
    return respond(c, 200, { client: toPublicClient(rotated.client), client_secret: rotated.secret });
  });

  const setDisabled = (enable: boolean) => async (c: Ctx) => {
    const clientId = c.req.param("clientId")!;
    const row = await getClient(clientId);
    if (!row) return notFound(c);
    if (enable && !row.is_public && !row.client_secret_hash) {
      return respond(c, 409, { error: "This client has no secret yet; rotate one before enabling it" });
    }
    const updated = await setClientDisabled(clientId, !enable);
    if (!updated) return notFound(c);
    record(c, enable ? "admin_oidc_client_enable" : "admin_oidc_client_disable", clientId);
    return respond(c, 200, toPublicClient(updated));
  };
  router.post("/clients/:clientId/disable", setDisabled(false));
  router.post("/clients/:clientId/enable", setDisabled(true));

  return router;
}
