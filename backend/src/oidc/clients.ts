import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { config } from "../config.ts";
import { sql } from "../db.ts";
import { internalTargetProblem } from "./net-safety.ts";
import { ADMIN_SCOPE, SUPPORTED_SCOPES } from "./scopes.ts";

export type OidcClientRow = {
  client_id: string;
  client_secret_hash: string | null;
  previous_secret_hash: string | null;
  previous_secret_expires_at: string | null;
  name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  backchannel_logout_uri: string | null;
  allowed_scopes: string[];
  is_public: boolean;
  disabled_at: string | null;
  created_at: string;
  updated_at: string;
};

const COLUMNS = `client_id, client_secret_hash, previous_secret_hash, previous_secret_expires_at, name, redirect_uris,
  post_logout_redirect_uris, backchannel_logout_uri, allowed_scopes, is_public, disabled_at, created_at, updated_at`;

// ---- secrets ------------------------------------------------------------

/** Client secrets are 256 random bits, so a plain SHA-256 is enough (as for refresh tokens). */
export const hashClientSecret = (secret: string) => createHash("sha256").update(secret).digest("hex");

export const generateClientSecret = () => randomBytes(32).toString("base64url");

/** Constant-time comparison of a presented secret with a stored hash. */
export function secretMatchesHash(presented: string, storedHash: string | null | undefined): boolean {
  if (!storedHash) return false;
  const given = Buffer.from(hashClientSecret(presented));
  const stored = Buffer.from(storedHash);
  return given.length === stored.length && timingSafeEqual(given, stored);
}

// ---- validation ---------------------------------------------------------

export class ClientValidationError extends Error {}

const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,62}$/;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
// Schemes that must never be a redirect target, whatever else the URI looks like.
const FORBIDDEN_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:", "about:", "blob:", "ws:", "wss:", "ftp:"]);

/** Why `value` cannot be used as a redirect (or logout) URI, or null when it can. */
function redirectUriProblem(value: unknown, isPublic: boolean): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 2000) return "must be a non-empty string";
  if (value.includes("*")) return "must not contain a wildcard";
  if (value.includes("#")) return "must not contain a fragment";
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URI";
  }
  if (url.username || url.password) return "must not contain credentials";
  if (FORBIDDEN_SCHEMES.has(url.protocol)) return `scheme ${url.protocol} is not allowed`;
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:") {
    return LOOPBACK_HOSTS.has(url.hostname) ? null : "http is only allowed for localhost";
  }
  // Anything else is a custom scheme, i.e. a native app claiming it.
  return isPublic ? null : "a custom scheme is only allowed for public (native) clients";
}

function uriList(value: unknown, field: string, isPublic: boolean, options: { min: number }): string[] {
  if (!Array.isArray(value)) throw new ClientValidationError(`${field} must be an array`);
  if (value.length < options.min) throw new ClientValidationError(`${field} must list at least ${options.min} URI`);
  if (value.length > 10) throw new ClientValidationError(`${field} may list at most 10 URIs`);
  for (const entry of value) {
    const problem = redirectUriProblem(entry, isPublic);
    if (problem) throw new ClientValidationError(`${field}: ${JSON.stringify(entry)} ${problem}`);
  }
  if (new Set(value).size !== value.length) throw new ClientValidationError(`${field} must not repeat a URI`);
  return value as string[];
}

export type ClientFields = {
  name: string;
  is_public: boolean;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  backchannel_logout_uri: string | null;
  allowed_scopes: string[];
};

/**
 * Validates the fields of a client, merged over `base` for a partial update.
 * Redirect URIs are matched exactly by the provider, so what is accepted here
 * is exactly what a client can ever be sent back to.
 */
export function validateClientFields(input: Record<string, unknown>, base?: ClientFields): ClientFields {
  const pick = <K extends keyof ClientFields>(key: K): unknown => (key in input ? input[key] : base?.[key]);

  const isPublic = pick("is_public");
  if (typeof isPublic !== "boolean") throw new ClientValidationError("is_public must be a boolean");

  const name = pick("name");
  if (typeof name !== "string" || name.trim().length === 0 || name.length > 100) {
    throw new ClientValidationError("name must be 1 to 100 characters");
  }

  const redirectUris = uriList(pick("redirect_uris"), "redirect_uris", isPublic, { min: 1 });
  const postLogout = uriList(pick("post_logout_redirect_uris") ?? [], "post_logout_redirect_uris", isPublic, { min: 0 });

  const backchannel = pick("backchannel_logout_uri") ?? null;
  if (backchannel !== null) {
    if (isPublic) throw new ClientValidationError("a public client cannot receive back-channel logout");
    const problem = redirectUriProblem(backchannel, false);
    if (problem) throw new ClientValidationError(`backchannel_logout_uri ${problem}`);
    // The server itself calls this URI, so it must not be able to aim at the local network.
    const internal = config.oidcAllowInternalBackchannel ? null : internalTargetProblem(backchannel as string);
    if (internal) throw new ClientValidationError(`backchannel_logout_uri ${internal}`);
  }

  const scopes = pick("allowed_scopes");
  if (!Array.isArray(scopes) || scopes.length === 0) throw new ClientValidationError("allowed_scopes must be a non-empty array");
  for (const scope of scopes) {
    if (typeof scope !== "string" || !SUPPORTED_SCOPES.includes(scope)) {
      throw new ClientValidationError(`allowed_scopes: unknown scope ${JSON.stringify(scope)}`);
    }
  }
  if (!scopes.includes("openid")) throw new ClientValidationError("allowed_scopes must include openid");
  if (new Set(scopes).size !== scopes.length) throw new ClientValidationError("allowed_scopes must not repeat a scope");

  return {
    name: name.trim(),
    is_public: isPublic,
    redirect_uris: redirectUris,
    post_logout_redirect_uris: postLogout,
    backchannel_logout_uri: backchannel as string | null,
    allowed_scopes: scopes as string[],
  };
}

// ---- storage ------------------------------------------------------------

export async function listClients(): Promise<OidcClientRow[]> {
  return sql<OidcClientRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_clients ORDER BY client_id;`;
}

export async function getClient(clientId: string): Promise<OidcClientRow | null> {
  const rows = await sql<OidcClientRow[]>`SELECT ${sql.unsafe(COLUMNS)} FROM oidc_clients WHERE client_id = ${clientId} LIMIT 1;`;
  return rows[0] ?? null;
}

export class ClientExistsError extends Error {}

/** Creates a client. A confidential client gets a secret, returned once and stored only as a hash. */
export async function createClient(
  clientId: string,
  fields: ClientFields,
  options: { disabled?: boolean; withoutSecret?: boolean } = {}
): Promise<{ client: OidcClientRow; secret: string | null }> {
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    throw new ClientValidationError("client_id must be 2-63 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit");
  }
  const secret = fields.is_public || options.withoutSecret ? null : generateClientSecret();
  const rows = await sql<OidcClientRow[]>`
    INSERT INTO oidc_clients (client_id, client_secret_hash, name, redirect_uris, post_logout_redirect_uris,
                              backchannel_logout_uri, allowed_scopes, is_public, disabled_at)
    VALUES (
      ${clientId},
      ${secret ? hashClientSecret(secret) : null},
      ${fields.name},
      ${sql.array(fields.redirect_uris, "TEXT")},
      ${sql.array(fields.post_logout_redirect_uris, "TEXT")},
      ${fields.backchannel_logout_uri},
      ${sql.array(fields.allowed_scopes, "TEXT")},
      ${fields.is_public},
      ${options.disabled ? new Date().toISOString() : null}
    )
    ON CONFLICT (client_id) DO NOTHING
    RETURNING ${sql.unsafe(COLUMNS)};
  `;
  if (rows.length === 0) throw new ClientExistsError(`client ${clientId} already exists`);
  return { client: rows[0], secret };
}

export async function updateClient(clientId: string, fields: ClientFields): Promise<OidcClientRow | null> {
  const rows = await sql<OidcClientRow[]>`
    UPDATE oidc_clients
    SET name = ${fields.name},
        redirect_uris = ${sql.array(fields.redirect_uris, "TEXT")},
        post_logout_redirect_uris = ${sql.array(fields.post_logout_redirect_uris, "TEXT")},
        backchannel_logout_uri = ${fields.backchannel_logout_uri},
        allowed_scopes = ${sql.array(fields.allowed_scopes, "TEXT")},
        updated_at = now()
    WHERE client_id = ${clientId}
    RETURNING ${sql.unsafe(COLUMNS)};
  `;
  return rows[0] ?? null;
}

/**
 * Replaces a confidential client's secret. The old one keeps working for
 * `graceSeconds`, so the relying party can be redeployed with the new one.
 * Refresh tokens are bound to the client, not to its secret, so they are
 * unaffected: rotating never signs anyone out.
 */
export async function rotateClientSecret(
  clientId: string,
  graceSeconds = config.oidcSecretRotationGraceSeconds
): Promise<{ client: OidcClientRow; secret: string } | null> {
  const secret = generateClientSecret();
  const rows = await sql<OidcClientRow[]>`
    UPDATE oidc_clients
    SET previous_secret_hash = CASE WHEN ${graceSeconds}::double precision > 0 THEN client_secret_hash END,
        previous_secret_expires_at = CASE WHEN ${graceSeconds}::double precision > 0 AND client_secret_hash IS NOT NULL
                                          THEN now() + make_interval(secs => ${graceSeconds}::double precision) END,
        client_secret_hash = ${hashClientSecret(secret)},
        updated_at = now()
    WHERE client_id = ${clientId} AND NOT is_public
    RETURNING ${sql.unsafe(COLUMNS)};
  `;
  return rows[0] ? { client: rows[0], secret } : null;
}

export async function setClientDisabled(clientId: string, disabled: boolean): Promise<OidcClientRow | null> {
  const rows = await sql<OidcClientRow[]>`
    UPDATE oidc_clients
    SET disabled_at = CASE WHEN ${disabled}::boolean THEN COALESCE(disabled_at, now()) ELSE NULL END,
        updated_at = now()
    WHERE client_id = ${clientId}
    RETURNING ${sql.unsafe(COLUMNS)};
  `;
  return rows[0] ?? null;
}

/** The registry row as the API shows it: never any secret material. */
export function toPublicClient(row: OidcClientRow) {
  return {
    client_id: row.client_id,
    name: row.name,
    is_public: row.is_public,
    redirect_uris: row.redirect_uris,
    post_logout_redirect_uris: row.post_logout_redirect_uris,
    backchannel_logout_uri: row.backchannel_logout_uri,
    allowed_scopes: row.allowed_scopes,
    disabled: row.disabled_at !== null,
    has_secret: row.client_secret_hash !== null,
    previous_secret_expires_at:
      row.previous_secret_hash && row.previous_secret_expires_at && new Date(row.previous_secret_expires_at) > new Date()
        ? row.previous_secret_expires_at
        : null,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// ---- what the provider library sees --------------------------------------

/** The two non-standard properties the provider is told to keep (see provider.ts `extraClientMetadata`). */
export const EXTRA_CLIENT_PROPERTIES = ["legacy_previous_secret_hash", "legacy_previous_secret_expires_at"];

const usesCustomScheme = (uri: string) => !/^https?:\/\//i.test(uri);

/**
 * Client metadata for the provider, or `undefined` for an unknown or disabled
 * client (the provider then answers `invalid_client`). A confidential client
 * without a secret is treated as unknown rather than letting it authenticate
 * with nothing.
 */
export async function findClientMetadata(clientId: string): Promise<Record<string, unknown> | undefined> {
  if (typeof clientId !== "string" || !CLIENT_ID_PATTERN.test(clientId)) return undefined;
  const row = await getClient(clientId);
  if (!row || row.disabled_at !== null) return undefined;
  if (!row.is_public && !row.client_secret_hash) return undefined;

  const previousStillValid =
    row.previous_secret_hash && row.previous_secret_expires_at && new Date(row.previous_secret_expires_at) > new Date();

  return {
    client_id: row.client_id,
    client_name: row.name,
    redirect_uris: row.redirect_uris,
    post_logout_redirect_uris: row.post_logout_redirect_uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: row.is_public ? "none" : "client_secret_basic",
    id_token_signed_response_alg: "ES256",
    scope: row.allowed_scopes.join(" "),
    // A client that is redirected to a custom scheme is a native app (the mobile app). The provider
    // always puts a native client through its consent step, so such a client cannot do `prompt=none`
    // and must show the browser instead. A web app, including one developed against http://localhost,
    // can.
    application_type: [...row.redirect_uris, ...row.post_logout_redirect_uris].some(usesCustomScheme) ? "native" : "web",
    ...(row.is_public ? {} : { client_secret: row.client_secret_hash }),
    ...(previousStillValid
      ? {
          legacy_previous_secret_hash: row.previous_secret_hash,
          legacy_previous_secret_expires_at: Math.floor(new Date(row.previous_secret_expires_at!).getTime() / 1000),
        }
      : {}),
    ...(row.backchannel_logout_uri
      ? { backchannel_logout_uri: row.backchannel_logout_uri, backchannel_logout_session_required: true }
      : {}),
  };
}

// ---- seeding --------------------------------------------------------------

/** The relying parties the issue registers up front. Seeded disabled: nothing changes for users until an admin enables them. */
function defaultClients(): { id: string; fields: ClientFields }[] {
  const issuerOrigin = new URL(config.jwtIssuer).origin;
  const web = (host: string, scopes: string[]): Omit<ClientFields, "name"> => ({
    is_public: false,
    redirect_uris: [`https://${host}/auth/callback`],
    post_logout_redirect_uris: [`https://${host}/`],
    backchannel_logout_uri: `https://${host}/auth/backchannel-logout`,
    allowed_scopes: scopes,
  });
  return [
    {
      id: "calendar-web",
      fields: { name: "Legacy Calendar", ...web("calendar.legacy-group.tech", ["openid", "profile", "calendar.read", "calendar.write", "offline_access"]) },
    },
    {
      id: "tracker-web",
      fields: { name: "Legacy Tracker (web)", ...web("tracker.legacy-group.tech", ["openid", "profile", "tracker.read", "tracker.write", "offline_access"]) },
    },
    {
      id: "tracker-mobile",
      fields: {
        name: "Legacy Tracker (mobile)",
        is_public: true,
        redirect_uris: ["com.legacy.legacytracker:/oauth2redirect"],
        post_logout_redirect_uris: [],
        backchannel_logout_uri: null,
        allowed_scopes: ["openid", "profile", "tracker.read", "tracker.write", "offline_access"],
      },
    },
    {
      id: "auth-console",
      fields: {
        name: "Legacy Auth console",
        is_public: false,
        redirect_uris: [`${issuerOrigin}/auth/callback`],
        post_logout_redirect_uris: [`${issuerOrigin}/`],
        backchannel_logout_uri: `${issuerOrigin}/auth/backchannel-logout`,
        allowed_scopes: ["openid", "profile", ADMIN_SCOPE, "offline_access"],
      },
    },
  ];
}

/** Inserts the default clients that are missing; existing rows are never touched. Returns the ids it added. */
export async function ensureDefaultClients(): Promise<string[]> {
  const added: string[] = [];
  for (const { id, fields } of defaultClients()) {
    try {
      // No secret yet: a confidential client is useless until an admin has seen one,
      // so the first rotate-secret call issues it.
      await createClient(id, validateClientFields({}, fields), { disabled: true, withoutSecret: true });
      added.push(id);
    } catch (error) {
      if (!(error instanceof ClientExistsError)) throw error;
    }
  }
  return added;
}
