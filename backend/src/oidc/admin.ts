import { withCorsHeaders } from "../cors.ts";
import type { AuthEvent } from "../db.ts";
import { jsonHeaders } from "../swagger.ts";
import type { UserRecord } from "../types.ts";
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

type AdminContext = {
  request: Request;
  url: URL;
  actor: UserRecord;
  audit: (entry: Omit<AuthEvent, "ip" | "userAgent">) => void;
};

const CLIENT_ID_IN_PATH = /^\/admin\/oidc\/clients\/([a-z0-9][a-z0-9._-]{1,62})(?:\/(rotate-secret|disable|enable))?$/;
const MAX_ROTATION_GRACE_SECONDS = 30 * 86400;

// Responses can carry a client secret, so none of them may be cached.
const respond = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: withCorsHeaders({ ...jsonHeaders, "cache-control": "no-store", pragma: "no-cache" }) });

const notFound = () => respond(404, { error: "Client not found" });

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

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
 * `/admin/oidc/clients…`: the registry of relying parties. The caller has
 * already checked that the user is an admin. Returns null for a path that is
 * not one of these, so the router can carry on.
 */
export async function handleOidcAdmin({ request, url, actor, audit }: AdminContext): Promise<Response | null> {
  const record = (event: string, clientId: string, detail?: string) =>
    audit({ event, success: true, userId: actor.id, username: actor.username, actorId: actor.id, detail: detail ? `${clientId}: ${detail}` : clientId });

  try {
    if (url.pathname === "/admin/oidc/clients") {
      if (request.method === "GET") {
        return respond(200, { items: (await listClients()).map(toPublicClient) });
      }
      if (request.method === "POST") {
        const body = await readBody(request);
        if (!body) return respond(400, { error: "A JSON object body is required" });
        const clientId = typeof body.client_id === "string" ? body.client_id : "";
        const fields = validateClientFields(body);
        const { client, secret } = await createClient(clientId, fields, { disabled: body.disabled === true });
        record("admin_oidc_client_create", clientId, fields.is_public ? "public" : "confidential");
        return respond(201, { client: toPublicClient(client), ...(secret ? { client_secret: secret } : {}) });
      }
      return null;
    }

    const match = url.pathname.match(CLIENT_ID_IN_PATH);
    if (!match) return null;
    const [, clientId, action] = match;

    if (!action && request.method === "GET") {
      const row = await getClient(clientId);
      return row ? respond(200, toPublicClient(row)) : notFound();
    }

    if (!action && request.method === "PATCH") {
      const row = await getClient(clientId);
      if (!row) return notFound();
      const body = await readBody(request);
      if (!body) return respond(400, { error: "A JSON object body is required" });
      if ("is_public" in body && body.is_public !== row.is_public) {
        return respond(400, { error: "is_public cannot be changed; register a new client instead" });
      }
      const unknown = Object.keys(body).filter((key) => !EDITABLE.includes(key) && key !== "is_public");
      if (unknown.length > 0) return respond(400, { error: `cannot update: ${unknown.join(", ")}` });
      const updated = await updateClient(clientId, validateClientFields(body, currentFields(row)));
      if (!updated) return notFound();
      record("admin_oidc_client_update", clientId, Object.keys(body).join(","));
      return respond(200, toPublicClient(updated));
    }

    if (action === "rotate-secret" && request.method === "POST") {
      const body = (await readBody(request)) ?? {};
      let grace: number | undefined;
      if ("grace_seconds" in body) {
        const value = body.grace_seconds;
        if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > MAX_ROTATION_GRACE_SECONDS) {
          return respond(400, { error: `grace_seconds must be between 0 and ${MAX_ROTATION_GRACE_SECONDS}` });
        }
        grace = value;
      }
      const row = await getClient(clientId);
      if (!row) return notFound();
      if (row.is_public) return respond(400, { error: "A public client has no secret" });
      const rotated = await rotateClientSecret(clientId, grace);
      if (!rotated) return notFound();
      record("admin_oidc_client_rotate_secret", clientId, `previous secret valid for ${grace ?? "the default grace period"}s`);
      return respond(200, { client: toPublicClient(rotated.client), client_secret: rotated.secret });
    }

    if ((action === "disable" || action === "enable") && request.method === "POST") {
      const row = await getClient(clientId);
      if (!row) return notFound();
      if (action === "enable" && !row.is_public && !row.client_secret_hash) {
        return respond(409, { error: "This client has no secret yet; rotate one before enabling it" });
      }
      const updated = await setClientDisabled(clientId, action === "disable");
      if (!updated) return notFound();
      record(action === "disable" ? "admin_oidc_client_disable" : "admin_oidc_client_enable", clientId);
      return respond(200, toPublicClient(updated));
    }

    return null;
  } catch (error) {
    if (error instanceof ClientValidationError) return respond(400, { error: error.message });
    if (error instanceof ClientExistsError) return respond(409, { error: error.message });
    throw error;
  }
}
