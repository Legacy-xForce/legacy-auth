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

type Document = {
  paths: Record<string, Record<string, unknown>>;
  components?: { schemas?: Record<string, unknown>; securitySchemes?: Record<string, unknown> };
  [key: string]: unknown;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Adds the proxy-only operations and the bearer scheme to a generated document. */
export function applyDocOverlay(document: Document): Document {
  for (const [path, item] of Object.entries(oidcPaths)) {
    if (!isObject(item)) continue;
    const existing = isObject(document.paths[path]) ? document.paths[path] : {};
    for (const [method, operation] of Object.entries(item)) {
      existing[method] = isObject(operation) && isObject(existing[method])
        ? { ...existing[method], ...operation }
        : operation;
    }
    document.paths[path] = existing;
  }

  document.components ??= {};
  document.components.securitySchemes = {
    ...document.components.securitySchemes,
    bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
  };
  return document;
}
