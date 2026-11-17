/**
 * The OpenID Provider's endpoints are served by `oidc-provider` on a private
 * Unix socket and proxied by this service — they are not Hono routes, so the
 * OpenAPI generator cannot discover them. They are kept here, verbatim, from
 * the old hand-written document. The tests pin several of these strings.
 */

export const oidcPaths: Record<string, unknown> = {
  "/.well-known/openid-configuration": {
    get: {
      tags: ["OpenID Provider"],
      summary: "OpenID Provider metadata",
      description:
        'Discovery document (OpenID Connect Discovery 1.0): the issuer, the endpoints below, the supported scopes and claims, `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`, `id_token_signing_alg_values_supported: ["ES256"]` and `backchannel_logout_supported: true`. Cacheable for five minutes.',
      responses: {
        "200": { description: "Provider metadata" },
        "404": { description: "The OpenID Provider is switched off (OIDC_ENABLED=false)" },
        "503": { description: "The OpenID Provider failed to start" },
      },
    },
  },
  "/authorize": {
    get: {
      tags: ["OpenID Provider"],
      summary: "Start a sign-in (Authorization Code with PKCE)",
      description:
        "Redirects the browser to the sign-in page when there is no session, and to `redirect_uri` with a `code` when there is. `redirect_uri` is required and must match a registered URI, or the same path on a subdomain of a registered web URI; an unregistered one gets an error page, never a redirect. `nonce` is required with the `openid` scope. `offline_access` only takes effect with `prompt=consent`, which is automatic and shows no screen. A request the user may not make comes back as `error=access_denied`.",
      parameters: [
        { name: "response_type", in: "query", required: true, schema: { type: "string", enum: ["code"] } },
        { name: "client_id", in: "query", required: true, schema: { type: "string" } },
        { name: "redirect_uri", in: "query", required: true, schema: { type: "string" } },
        { name: "scope", in: "query", required: true, schema: { type: "string", example: "openid profile calendar.read calendar.write offline_access" } },
        { name: "resource", in: "query", schema: { type: "string", enum: ["urn:legacy:calendar", "urn:legacy:tracker"] }, description: "The app whose API the access token is for. The token's `aud` is `calendar` or `tracker`." },
        { name: "code_challenge", in: "query", required: true, schema: { type: "string" } },
        { name: "code_challenge_method", in: "query", required: true, schema: { type: "string", enum: ["S256"] } },
        { name: "state", in: "query", schema: { type: "string" }, description: "Returned unchanged." },
        { name: "nonce", in: "query", schema: { type: "string" }, description: "Required with `openid`; echoed in the ID token." },
        { name: "prompt", in: "query", schema: { type: "string", example: "consent" }, description: "`none`, `login`, `consent`; use `consent` with `offline_access`." },
        { name: "max_age", in: "query", schema: { type: "integer" } },
        { name: "login_hint", in: "query", schema: { type: "string" } },
      ],
      responses: {
        "303": { description: "Redirect to the sign-in page, or to `redirect_uri` with `code`, `state` and `iss` (or `error` and `error_description`)" },
        "400": { description: "The request cannot be trusted with a redirect: unknown client, unregistered or missing `redirect_uri`, missing `nonce`" },
        "429": { description: "Too many malformed requests from this address; see Retry-After" },
      },
    },
  },
  "/token": {
    post: {
      tags: ["OpenID Provider"],
      summary: "Redeem a code or a refresh token",
      description:
        "`grant_type=authorization_code` (with `code`, `redirect_uri`, `code_verifier`) or `grant_type=refresh_token`. Confidential clients authenticate with `client_secret_basic`; public clients send `client_id` and no secret. A code works once and for 60 seconds. Presenting a rotated refresh token again revokes the whole grant. Never cached.",
      requestBody: {
        required: true,
        content: { "application/x-www-form-urlencoded": { schema: { $ref: "#/components/schemas/OidcTokenRequest" } } },
      },
      responses: {
        "200": { description: "`access_token` (a JWT for the requested resource), `id_token`, `refresh_token` (with `offline_access`), `expires_in`, `scope`, `token_type`" },
        "400": { description: "`invalid_grant`, `invalid_request`, `unsupported_grant_type`, ..." },
        "401": { description: "`invalid_client`" },
        "429": { description: "Too many failed requests from this address; see Retry-After" },
      },
    },
  },
  "/userinfo": {
    get: {
      tags: ["OpenID Provider"],
      summary: "Claims about the signed-in user",
      description:
        "Returns `sub`, `preferred_username`, `name` and `role`. `preferred_username` is the lowercase login identifier; `name` is the user's display name. Needs a bearer token with the `openid` scope that was requested *without* a `resource`: an access token for an app's API is for that app, not for the provider.",
      security: [{ bearerAuth: [] }],
      responses: { "200": { description: "Claims" }, "401": { description: "Missing, invalid or resource-bound token" } },
    },
  },
  "/logout": {
    get: {
      tags: ["OpenID Provider"],
      summary: "RP-initiated logout",
      description:
        "With an `id_token_hint` the page submits itself; without one it asks first. Ending the session signs the user out of every app (each gets a back-channel logout) and revokes their refresh tokens. Redirects only to a registered `post_logout_redirect_uri`.",
      parameters: [
        { name: "id_token_hint", in: "query", schema: { type: "string" } },
        { name: "post_logout_redirect_uri", in: "query", schema: { type: "string" } },
        { name: "state", in: "query", schema: { type: "string" } },
        { name: "client_id", in: "query", schema: { type: "string" } },
      ],
      responses: { "200": { description: "The logout page" }, "303": { description: "Redirect to the registered post-logout address" }, "400": { description: "Unregistered `post_logout_redirect_uri`" } },
    },
  },
};

/** Documents operations whose runtime validation is intentionally left to the handler. */
export const docsOnlyPaths: Record<string, unknown> = {
  "/auth/passkey/login-options": {
    post: {
      tags: ["Passkey"],
      summary: "Generate WebAuthn login options",
      deprecated: true,
      description: "Deprecated with `/auth/login`; passkeys are an authentication method at the OpenID Provider's sign-in page.",
      requestBody: {
        required: false,
        content: { "application/json": { schema: { type: "object", properties: { username: { type: "string" } } } } },
      },
      responses: { "200": { description: "WebAuthn assertion options" } },
    },
  },
  "/auth/passkey/login-verify": {
    post: {
      tags: ["Passkey"],
      summary: "Verify WebAuthn assertion and issue tokens",
      deprecated: true,
      description: "Deprecated with `/auth/login`. Body is the WebAuthn assertion (`id`, `rawId`, `response`) plus an optional `audience`, as for `/auth/login`.",
      requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
      responses: {
        "200": { description: "Tokens issued successfully", content: { "application/json": { schema: { $ref: "#/components/schemas/TokenResponse" } } } },
        "400": { description: "Unknown audience" },
        "401": { description: "Invalid passkey signature or replay detected" },
        "403": { description: "Account disabled, or no access to the requested audience" },
        "429": { description: "Too many failed attempts; see the Retry-After header" },
      },
    },
  },
  "/auth/passkey/register-options": {
    post: {
      tags: ["Passkey"],
      summary: "Generate WebAuthn registration options",
      security: [{ bearerAuth: [] }],
      responses: { "200": { description: "WebAuthn creation options" }, "401": { description: "Unauthorized" } },
    },
  },
  "/auth/passkey/register-verify": {
    post: {
      tags: ["Passkey"],
      summary: "Verify WebAuthn registration and store passkey credential",
      security: [{ bearerAuth: [] }],
      requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
      responses: {
        "200": { description: "Credential registered successfully" },
        "400": { description: "Invalid credential payload" },
        "401": { description: "Unauthorized" },
        "409": { description: "The credential id is registered to another account" },
      },
    },
  },
  "/auth/passkey/credentials": {
    get: {
      tags: ["Passkey"],
      summary: "List registered passkeys for current user",
      security: [{ bearerAuth: [] }],
      responses: { "200": { description: "List of registered passkeys" }, "401": { description: "Unauthorized" } },
    },
  },
  "/auth/passkey/credentials/{id}": {
    delete: {
      tags: ["Passkey"],
      summary: "Delete a registered passkey",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "Passkey deleted" }, "401": { description: "Unauthorized" }, "404": { description: "Passkey not found" } },
    },
  },
  "/auth/profile-picture": {
    post: {
      tags: ["Profile"],
      summary: "Upload the authenticated user's profile picture",
      description: "Accepts JPEG, PNG, WebP, AVIF, or GIF images. Every image is resized to 256x256 (cropped to fit) and re-encoded as WebP. Animated input stays animated; transparency is preserved.",
      security: [{ bearerAuth: [] }],
      requestBody: {
        required: true,
        content: { "multipart/form-data": { schema: { type: "object", required: ["file"], properties: { file: { type: "string", format: "binary" } } } } },
      },
      responses: {
        "200": { description: "Profile picture stored successfully", content: { "application/json": { schema: { $ref: "#/components/schemas/UploadProfilePictureResponse" } } } },
        "400": { description: "Missing file, unsupported format, or corrupted image" },
        "401": { description: "Invalid access token" },
        "403": { description: "Account disabled" },
        "413": { description: "File exceeds maximum upload size" },
      },
    },
  },
  "/auth/profile-picture/{userId}": {
    get: {
      tags: ["Profile"],
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
    },
  },
  "/admin/oidc/clients": {
    get: {
      tags: ["Admin"],
      summary: "List registered OpenID clients",
      security: [{ bearerAuth: [] }],
      responses: {
        "200": { description: "Clients, never with secret material", content: { "application/json": { schema: { type: "object", properties: { items: { type: "array", items: { $ref: "#/components/schemas/OidcClient" } } } } } } },
        "401": { description: "Missing or invalid access token" },
        "403": { description: "Admin role required" },
      },
    },
    post: {
      tags: ["Admin"],
      summary: "Register an OpenID client",
      description: "A confidential client gets a secret, returned once in `client_secret`; only its hash is stored.",
      security: [{ bearerAuth: [] }],
      requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/CreateOidcClientRequest" } } } },
      responses: {
        "201": { description: "Created", content: { "application/json": { schema: { type: "object", properties: { client: { $ref: "#/components/schemas/OidcClient" }, client_secret: { type: "string" } } } } } },
        "400": { description: "Invalid field (redirect URI rules, scopes, client_id, ...)" },
        "401": { description: "Missing or invalid access token" },
        "403": { description: "Admin role required" },
        "409": { description: "client_id already exists" },
      },
    },
  },
  "/admin/oidc/clients/{clientId}": {
    get: {
      tags: ["Admin"],
      summary: "Read one OpenID client",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "clientId", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "The client", content: { "application/json": { schema: { $ref: "#/components/schemas/OidcClient" } } } }, "404": { description: "Unknown client" } },
    },
    patch: {
      tags: ["Admin"],
      summary: "Update an OpenID client",
      description: "Any of `name`, `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_uri`, `allowed_scopes`. `is_public` cannot change; other fields are refused.",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "clientId", in: "path", required: true, schema: { type: "string" } }],
      requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/UpdateOidcClientRequest" } } } },
      responses: { "200": { description: "The updated client" }, "400": { description: "Invalid or unknown field" }, "404": { description: "Unknown client" } },
    },
  },
  "/admin/oidc/clients/{clientId}/rotate-secret": {
    post: {
      tags: ["Admin"],
      summary: "Issue a new client secret",
      description: "The new secret is returned once. The previous one keeps working for `grace_seconds` (default OIDC_SECRET_ROTATION_GRACE_SECONDS; 0 revokes it at once). Refresh tokens are unaffected.",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "clientId", in: "path", required: true, schema: { type: "string" } }],
      requestBody: { required: false, content: { "application/json": { schema: { type: "object", properties: { grace_seconds: { type: "number", minimum: 0, maximum: 2592000 } } } } } },
      responses: { "200": { description: "The client and its new `client_secret`" }, "400": { description: "A public client has no secret, or the grace period is out of range" }, "404": { description: "Unknown client" } },
    },
  },
  "/admin/oidc/clients/{clientId}/disable": {
    post: {
      tags: ["Admin"],
      summary: "Disable an OpenID client",
      description: "A disabled client gets `invalid_client` from every endpoint, refreshes included.",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "clientId", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "The client" }, "404": { description: "Unknown client" } },
    },
  },
  "/admin/oidc/clients/{clientId}/enable": {
    post: {
      tags: ["Admin"],
      summary: "Enable an OpenID client",
      description: "A confidential client needs a secret first (see rotate-secret).",
      security: [{ bearerAuth: [] }],
      parameters: [{ name: "clientId", in: "path", required: true, schema: { type: "string" } }],
      responses: { "200": { description: "The client" }, "404": { description: "Unknown client" }, "409": { description: "The client has no secret yet" } },
    },
  },
};

type Document = {
  paths: Record<string, Record<string, unknown>>;
  components?: { schemas?: Record<string, unknown>; securitySchemes?: Record<string, unknown> };
  [key: string]: unknown;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Shallow-merge per path + per method so generated operations are overridden cleanly. */
function mergePaths(target: Record<string, Record<string, unknown>>, overlay: Record<string, unknown>) {
  for (const [path, item] of Object.entries(overlay)) {
    if (!isObject(item)) continue;
    const existing = isObject(target[path]) ? target[path] : {};
    for (const [method, operation] of Object.entries(item)) {
      existing[method] = isObject(operation) && isObject(existing[method])
        ? { ...existing[method], ...operation }
        : operation;
    }
    target[path] = existing;
  }
}

/** Adds the proxy-only operations and the documented-only request bodies to a generated document. */
export function applyDocOverlay(document: Document): Document {
  mergePaths(document.paths, oidcPaths);
  mergePaths(document.paths, docsOnlyPaths);

  document.components ??= {};
  document.components.securitySchemes = {
    ...document.components.securitySchemes,
    bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
  };
  return document;
}
