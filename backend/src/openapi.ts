import { config } from "./config.ts";

type OpenApiDocument = {
  openapi: string;
  info: {
    title: string;
    version: string;
    description: string;
  };
  servers: Array<{ url: string }>;
  paths: Record<string, unknown>;
  components: {
    schemas: Record<string, unknown>;
    securitySchemes: Record<string, unknown>;
  };
};

export function createOpenApiDocument(): OpenApiDocument {
  return {
    openapi: "3.0.3",
    info: {
      title: "Legacy Auth Service",
      version: "0.1.0",
      description: "Authentication service for the Legacy ecosystem.",
    },
    servers: [{ url: "/" }],
    paths: {
      "/auth/login": {
        post: {
          tags: ["Auth"],
          summary: "Authenticate a user and issue tokens",
          deprecated: true,
          description: "Deprecated: the Resource Owner Password Credentials grant. Use the OpenID Provider (`/.well-known/openid-configuration`). Still honours `audience`; every response carries `Deprecation: true`.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/LoginRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Tokens issued successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/TokenResponse" },
                },
              },
            },
            "400": { description: "Missing username or password, or unknown audience" },
            "401": { description: "Invalid credentials" },
            "403": { description: "Account disabled, or no access to the requested audience" },
            "429": { description: "Too many failed attempts; see the Retry-After header" },
          },
        },
      },
      "/auth/change-password": {
        post: {
          tags: ["Auth"],
          summary: "Change the authenticated user's password",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/ChangePasswordRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Password changed successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ChangePasswordResponse" },
                },
              },
            },
            "400": { description: "Missing current_password or new_password" },
            "401": { description: "Invalid access token or current password" },
            "403": { description: "Account disabled" },
            "429": { description: "Too many failed attempts; see the Retry-After header" },
          },
        },
      },
      "/auth/passkey/login-options": {
        post: {
          tags: ["Passkey"],
          summary: "Generate WebAuthn login options",
          deprecated: true,
          description: "Deprecated with `/auth/login`; passkeys are an authentication method at the OpenID Provider's sign-in page.",
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { username: { type: "string" } },
                },
              },
            },
          },
          responses: {
            "200": { description: "WebAuthn assertion options" },
          },
        },
      },
      "/auth/passkey/login-verify": {
        post: {
          tags: ["Passkey"],
          summary: "Verify WebAuthn assertion and issue tokens",
          deprecated: true,
          description: "Deprecated with `/auth/login`. Body is the WebAuthn assertion (`id`, `rawId`, `response`) plus an optional `audience`, as for `/auth/login`.",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
          responses: {
            "200": {
              description: "Tokens issued successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/TokenResponse" },
                },
              },
            },
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
          responses: {
            "200": { description: "WebAuthn creation options" },
            "401": { description: "Unauthorized" },
          },
        },
      },
      "/auth/passkey/register-verify": {
        post: {
          tags: ["Passkey"],
          summary: "Verify WebAuthn registration and store passkey credential",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
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
          responses: {
            "200": { description: "List of registered passkeys" },
            "401": { description: "Unauthorized" },
          },
        },
      },
      "/auth/passkey/credentials/{id}": {
        delete: {
          tags: ["Passkey"],
          summary: "Delete a registered passkey",
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          responses: {
            "200": { description: "Passkey deleted" },
            "401": { description: "Unauthorized" },
            "404": { description: "Passkey not found" },
          },
        },
      },
      "/auth/refresh": {
        post: {
          tags: ["Auth"],
          summary: "Exchange a refresh token for a new token pair",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RefreshRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Tokens refreshed successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/TokenResponse" },
                },
              },
            },
            "400": { description: "Missing refresh_token" },
            "401": { description: "Invalid, revoked, or expired refresh token" },
            "403": { description: "Account disabled, or no longer has access to the session's audience" },
          },
        },
      },
      "/auth/logout": {
        post: {
          tags: ["Auth"],
          summary: "Revoke a refresh token",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/RefreshRequest" },
              },
            },
          },
          responses: {
            "200": {
              description: "Refresh token revoked",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/LogoutResponse" },
                },
              },
            },
            "400": { description: "Missing refresh_token" },
            "401": { description: "Invalid refresh token" },
          },
        },
      },
      "/auth/profile-picture": {
        post: {
          tags: ["Profile"],
          summary: "Upload the authenticated user's profile picture",
          description: "Accepts JPEG, PNG, WebP, or GIF images. Non-GIF images are resized to 256x256 and re-encoded as compressed JPEG. GIFs are resized to 256x256 and kept as GIF so animation is preserved.",
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "multipart/form-data": {
                schema: {
                  type: "object",
                  required: ["file"],
                  properties: {
                    file: { type: "string", format: "binary" },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Profile picture stored successfully",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/UploadProfilePictureResponse" },
                },
              },
            },
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
          parameters: [
            {
              name: "userId",
              in: "path",
              required: true,
              schema: { type: "string", format: "uuid" },
            },
          ],
          responses: {
            "200": {
              description: "Profile picture image bytes (image/jpeg or image/gif)",
              content: {
                "image/jpeg": { schema: { type: "string", format: "binary" } },
                "image/gif": { schema: { type: "string", format: "binary" } },
              },
            },
            "400": { description: "Invalid user id" },
            "404": { description: "No profile picture stored for this user" },
          },
        },
      },
      "/.well-known/jwks.json": {
        get: {
          tags: ["Keys"],
          summary: "JSON Web Key Set",
          description: "Returns the public keys used to verify access token signatures (ES256). Consumers can use this endpoint to validate JWTs without sharing any secret.",
          responses: {
            "200": {
              description: "JWKS document",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/JwksResponse" },
                },
              },
            },
          },
        },
      },
      "/.well-known/assetlinks.json": {
        get: {
          tags: ["Keys"],
          summary: "Digital Asset Links",
          description: "Lists the Android apps (package and signing certificate SHA-256) allowed to use this host's passkeys, from PASSKEY_ANDROID_APPS.",
          responses: {
            "200": {
              description: "Asset Links statements",
            },
            "404": {
              description: "No Android apps configured",
            },
          },
        },
      },
      "/.well-known/openid-configuration": {
        get: {
          tags: ["OpenID Provider"],
          summary: "OpenID Provider metadata",
          description: "Discovery document (OpenID Connect Discovery 1.0): the issuer, the endpoints below, the supported scopes and claims, `response_types_supported: [\"code\"]`, `code_challenge_methods_supported: [\"S256\"]`, `id_token_signing_alg_values_supported: [\"ES256\"]` and `backchannel_logout_supported: true`. Cacheable for five minutes.",
          responses: { "200": { description: "Provider metadata" }, "404": { description: "The OpenID Provider is switched off (OIDC_ENABLED=false)" }, "503": { description: "The OpenID Provider failed to start" } },
        },
      },
      "/authorize": {
        get: {
          tags: ["OpenID Provider"],
          summary: "Start a sign-in (Authorization Code with PKCE)",
          description:
            "Redirects the browser to the sign-in page when there is no session, and to `redirect_uri` with a `code` when there is. `redirect_uri` is required and must match a registered URI exactly; an unregistered one gets an error page, never a redirect. `nonce` is required with the `openid` scope. `offline_access` only takes effect with `prompt=consent`, which is automatic and shows no screen. A request the user may not make comes back as `error=access_denied`.",
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
          description: "Returns `sub`, `preferred_username`, `name` and `role`. `preferred_username` is the lowercase login identifier; `name` is the user's display name. Needs a bearer token with the `openid` scope that was requested *without* a `resource`: an access token for an app's API is for that app, not for the provider.",
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
      "/admin/audit-events": {
        get: {
          tags: ["Admin"],
          summary: "List audit events",
          description: `Sign-ins, refreshes, password and passkey changes and admin changes, newest first. Rows older than the retention period (AUDIT_RETENTION_DAYS, currently ${config.auditRetentionDays} days; 0 keeps everything) are pruned daily. Admin only.`,
          security: [{ bearerAuth: [] }],
          parameters: [
            { name: "event", in: "query", schema: { type: "string" }, description: "Exact event name, e.g. `login`, `refresh`, `passkey_login`." },
            { name: "success", in: "query", schema: { type: "boolean" } },
            { name: "userId", in: "query", schema: { type: "string", format: "uuid" } },
            { name: "username", in: "query", schema: { type: "string" }, description: "Exact, case-insensitive." },
            { name: "since", in: "query", schema: { type: "string", format: "date-time" }, description: "Inclusive." },
            { name: "until", in: "query", schema: { type: "string", format: "date-time" }, description: "Exclusive." },
            { name: "page", in: "query", schema: { type: "integer", minimum: 1, default: 1 } },
            { name: "pageSize", in: "query", schema: { type: "integer", minimum: 1, maximum: 200, default: 50 } },
          ],
          responses: {
            "200": {
              description: "A page of audit events",
              content: { "application/json": { schema: { $ref: "#/components/schemas/AuditEventsResponse" } } },
            },
            "400": { description: "A filter is malformed" },
            "401": { description: "Missing or invalid access token" },
            "403": { description: "Admin role required" },
          },
        },
      },
      "/openapi.json": {
        get: {
          tags: ["Docs"],
          summary: "OpenAPI document",
          responses: {
            "200": {
              description: "OpenAPI JSON document",
            },
          },
        },
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        LoginRequest: {
          type: "object",
          required: ["username", "password"],
          properties: {
            username: { type: "string", example: "alice" },
            password: { type: "string", example: "secret" },
            audience: {
              type: "string",
              enum: ["calendar", "tracker"],
              description:
                "The app the session is for. The access token's `aud` is then just this app, and the request is refused when the user's scopes do not include it. Omitted, `aud` lists every app the user's scopes allow — unless the service runs with REQUIRE_AUDIENCE=true, in which case omitting it is a 400.",
            },
          },
        },
        RefreshRequest: {
          type: "object",
          required: ["refresh_token"],
          properties: {
            refresh_token: { type: "string", example: "eyJhbGciOi..." },
          },
        },
        ChangePasswordRequest: {
          type: "object",
          required: ["current_password", "new_password"],
          properties: {
            current_password: { type: "string", example: "old-secret" },
            new_password: { type: "string", example: "new-secret" },
          },
        },
        ChangePasswordResponse: {
          type: "object",
          required: ["success"],
          properties: {
            success: { type: "boolean", example: true },
          },
        },
        TokenResponse: {
          type: "object",
          required: ["access_token", "refresh_token", "expires_in", "refresh_expires_in"],
          properties: {
            access_token: { type: "string" },
            refresh_token: { type: "string" },
            expires_in: { type: "integer", example: config.accessTokenTtlSeconds },
            refresh_expires_in: { type: "integer", example: config.refreshTokenTtlSeconds },
          },
        },
        LogoutResponse: {
          type: "object",
          required: ["success"],
          properties: {
            success: { type: "boolean", example: true },
          },
        },
        UploadProfilePictureResponse: {
          type: "object",
          required: ["success", "content_type"],
          properties: {
            success: { type: "boolean", example: true },
            content_type: { type: "string", example: "image/jpeg" },
          },
        },
        OidcTokenRequest: {
          type: "object",
          required: ["grant_type"],
          properties: {
            grant_type: { type: "string", enum: ["authorization_code", "refresh_token"] },
            code: { type: "string" },
            redirect_uri: { type: "string" },
            code_verifier: { type: "string" },
            refresh_token: { type: "string" },
            client_id: { type: "string", description: "Public clients only; confidential clients authenticate with HTTP Basic." },
          },
        },
        OidcClient: {
          type: "object",
          properties: {
            client_id: { type: "string", example: "calendar-web" },
            name: { type: "string" },
            is_public: { type: "boolean" },
            redirect_uris: { type: "array", items: { type: "string" } },
            post_logout_redirect_uris: { type: "array", items: { type: "string" } },
            backchannel_logout_uri: { type: "string", nullable: true },
            allowed_scopes: { type: "array", items: { type: "string" } },
            disabled: { type: "boolean" },
            has_secret: { type: "boolean" },
            previous_secret_expires_at: { type: "string", format: "date-time", nullable: true, description: "While set, the previous secret still works." },
            created_at: { type: "string", format: "date-time" },
            updated_at: { type: "string", format: "date-time" },
          },
        },
        CreateOidcClientRequest: {
          type: "object",
          required: ["client_id", "name", "is_public", "redirect_uris", "allowed_scopes"],
          properties: {
            client_id: { type: "string", pattern: "^[a-z0-9][a-z0-9._-]{1,62}$" },
            name: { type: "string" },
            is_public: { type: "boolean" },
            redirect_uris: { type: "array", items: { type: "string" }, description: "Matched exactly. https, or http on localhost; a custom scheme only for a public client. No wildcards or fragments." },
            post_logout_redirect_uris: { type: "array", items: { type: "string" } },
            backchannel_logout_uri: { type: "string", nullable: true, description: "Confidential clients only; may not point at a private network in production." },
            allowed_scopes: { type: "array", items: { type: "string" }, description: "Must include `openid`." },
            disabled: { type: "boolean" },
          },
        },
        UpdateOidcClientRequest: {
          type: "object",
          properties: {
            name: { type: "string" },
            redirect_uris: { type: "array", items: { type: "string" } },
            post_logout_redirect_uris: { type: "array", items: { type: "string" } },
            backchannel_logout_uri: { type: "string", nullable: true },
            allowed_scopes: { type: "array", items: { type: "string" } },
          },
        },
        AuditEventsResponse: {
          type: "object",
          required: ["items", "total", "page", "pageSize", "retention_days"],
          properties: {
            items: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  event: { type: "string", example: "login" },
                  success: { type: "boolean" },
                  user_id: { type: "string", format: "uuid", nullable: true },
                  username: { type: "string", nullable: true },
                  actor_id: { type: "string", format: "uuid", nullable: true, description: "The admin, for admin actions." },
                  ip: { type: "string", nullable: true },
                  user_agent: { type: "string", nullable: true },
                  detail: { type: "string", nullable: true },
                  created_at: { type: "string", format: "date-time" },
                },
              },
            },
            total: { type: "integer" },
            page: { type: "integer" },
            pageSize: { type: "integer" },
            retention_days: { type: "integer", description: "0 means rows are kept forever." },
          },
        },
        JwksResponse: {
          type: "object",
          required: ["keys"],
          properties: {
            keys: {
              type: "array",
              items: {
                type: "object",
                required: ["kty", "crv", "x", "y", "use", "alg", "kid"],
                properties: {
                  kty: { type: "string", example: "EC" },
                  crv: { type: "string", example: "P-256" },
                  x: { type: "string", description: "Base64url-encoded x coordinate" },
                  y: { type: "string", description: "Base64url-encoded y coordinate" },
                  use: { type: "string", example: "sig" },
                  alg: { type: "string", example: "ES256" },
                  kid: { type: "string", description: "Key ID (RFC 7638 thumbprint)" },
                },
              },
            },
          },
        },
      },
    },
  };
}
