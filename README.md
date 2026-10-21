# Legacy Auth

A lightweight Bun-based authentication service for the Legacy ecosystem, plus a Vue 3 management console for administering users.

This is a monorepo (Bun workspaces):

- [`backend/`](backend) — the auth API (Bun, PostgreSQL, JWT).
- [`frontend/`](frontend) — the Vue 3 + Vite management console.

In production (see [Docker](#docker)), the backend serves the built frontend as static files on the same port, so the whole app is a single deployable image.

## Features

- An OpenID Provider (`/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`, `/logout`): Authorization Code + PKCE, a shared browser session across apps, and back-channel logout. See [OpenID Provider](#openid-provider).
- `POST /auth/login` to authenticate users (deprecated in favour of the OpenID Provider; see [Retiring password login](#retiring-password-login))
- `POST /auth/passkey/login-options` & `POST /auth/passkey/login-verify` for passkey / biometric authentication
- `POST /auth/passkey/register-options` & `POST /auth/passkey/register-verify` to register passkeys
- `GET /auth/passkey/credentials` & `DELETE /auth/passkey/credentials/:id` to manage registered passkeys
- `POST /auth/refresh` to refresh access tokens
- `POST /auth/logout` to revoke refresh tokens
- `POST /auth/change-password` to change the authenticated user's password
- `GET /auth/me` / `PATCH /auth/me` to read/update the authenticated user's own profile
- `POST /auth/profile-picture` to upload a profile picture (resized to 256x256, JPEG-compressed; GIFs stay animated)
- `GET /auth/profile-picture/:userId` to fetch a user's profile picture
- Admin user management: list/create/update users, roles, active status, and per-app scopes (see [Admin API](#admin-api))
- Failed sign-in throttling and an `auth_events` audit log with retention and an admin view (see [Throttling and audit log](#throttling-and-audit-log))
- Swagger UI at `GET /docs`
- OpenAPI spec at `GET /openapi.json`
- JWT access tokens (ES256) + refresh tokens (HS256)
- JWKS endpoint at `GET /.well-known/jwks.json` for public key discovery
- in-memory username/password cache
- PostgreSQL backed refresh token revocation
- Bun password hashing with Argon2 for new passwords
- Bun password verification for both Argon2 and legacy bcrypt hashes

## Environment

Required environment variables:

- `DATABASE_URL` - Postgres connection string
- `JWT_SECRET` - secret used to sign refresh tokens (HS256), and from which the OpenID Provider's cookie-signing key is derived
- `JWT_PRIVATE_KEY` - EC P-256 private key in PEM format used to sign access tokens (ES256). If unset, an ephemeral key is generated at startup — tokens will be invalidated on restart.

**In production (`NODE_ENV=production`, which the Docker image sets) the service refuses to start** unless `JWT_SECRET` is set and is not a well-known placeholder (including the one in `backend/.env.example`), and `JWT_PRIVATE_KEY` is a valid EC P-256 key other than the example one. Both are checked before anything else runs, so a misconfigured deployment fails at once instead of quietly signing with a default or a throwaway key. Outside production the old behaviour (a built-in secret, an ephemeral key, a warning) is unchanged.

Optional environment variables:

- `JWT_KEY_ID` - override the `kid` claim in access tokens and the JWKS response. Defaults to the RFC 7638 SHA-256 thumbprint of the public key.
- `JWT_ISSUER` - the `iss` claim of access tokens (default: `https://auth.legacy-group.tech`). Apps that accept these tokens must expect the same value.
- `CORS_ALLOWED_ORIGINS` - comma-separated browser origins allowed to call the API (e.g. `https://calendar.legacy-group.tech,https://tracker.legacy-group.tech`). Unset, any origin is allowed and a warning is logged at startup. The console is served from this service's own origin and does not need to be listed.
- `LOGIN_MAX_FAILURES` (default: `10`) and `LOGIN_FAILURE_WINDOW_SECONDS` (default: `900`) - failed sign-ins tolerated per username within the window (each client IP gets five times as many) before further attempts get `429`
- `TRUST_PROXY` - set to `true` behind a reverse proxy (e.g. a Cloudflare Tunnel) so the client IP is read from `X-Forwarded-For`. The header is only believed when the connection comes from a private address, and the rightmost public entry is used, since entries to its left are whatever the client sent.
- `REQUIRE_AUDIENCE` (default: `false`) - when `true`, `/auth/login` and passkey login refuse a request that does not name an `audience` (`400`), and the "every scoped app" fallback is gone. Turn it on once every client sends `audience`; refreshing a session opened without one keeps working until it expires. See [Retiring password login](#retiring-password-login).
- `AUDIT_RETENTION_DAYS` (default: `180`) - `auth_events` rows older than this are deleted daily; `0` keeps them forever. Anything that is not a whole number falls back to `180` with a warning rather than pruning on a typo.
- `OIDC_ENABLED` (default: `true`) - set to `false` to switch the OpenID Provider off entirely (its paths answer `404`; nothing else changes). This is the rollback.
- `OIDC_COOKIE_KEYS` - comma-separated keys that sign the OP's cookies, newest first, for rotating them. Unset, one is derived from `JWT_SECRET`.
- `OIDC_SESSION_IDLE_SECONDS` (default: `1209600`, 14 days) and `OIDC_SESSION_ABSOLUTE_SECONDS` (default: `2592000`, 30 days) - a browser session ends after this long without activity, or this long after sign-in, whichever comes first.
- `OIDC_SECRET_ROTATION_GRACE_SECONDS` (default: `86400`) - how long a client's previous secret keeps working after `rotate-secret`.
- `OIDC_BACKCHANNEL_RETRY_DELAYS_MS` (default: `5000,30000,120000,600000,3600000`) and `OIDC_BACKCHANNEL_POLL_MS` (default: `2000`) - back-channel logout retries.
- `OIDC_ALLOW_INTERNAL_BACKCHANNEL` (default: `true` outside production, `false` in it) - whether a client's back-channel logout URI may point at localhost or a private network.
- `PORT` (default: `4000`)
- `ACCESS_TOKEN_TTL_SECONDS` (default: `900`)
- `REFRESH_TOKEN_TTL_SECONDS` (default: `2592000`)
- `REFRESH_REUSE_GRACE_SECONDS` (default: `30`) - how long a rotated refresh token can still be refreshed (see [Refresh](#refresh))
- `CACHE_TTL_MS` (default: `300000`)
- `AVATAR_STORAGE_DIR` - directory where profile picture files are stored on disk, relative to `backend/` (default: `./data/avatars`)
- `AVATAR_MAX_UPLOAD_BYTES` - maximum accepted profile picture upload size in bytes (default: `8388608`, i.e. 8 MiB)
- `FRONTEND_DIST_DIR` - directory of the built frontend to serve as static files, relative to `backend/` (default: `../frontend/dist`). If missing, the backend simply serves the API and returns `404` for unknown routes.
- `PASSKEY_ANDROID_APPS` - comma-separated `<package>:<SHA-256 signing certificate fingerprint>` entries for Android apps allowed to use this host's passkeys (see [Android apps](#android-apps)). Unset, `/.well-known/assetlinks.json` returns `404`.

Backend environment variables go in `backend/.env` (see `backend/.env.example`). The frontend has its own `frontend/.env` for `VITE_API_URL` (see `frontend/.env.example`) — only needed for local development against a separately-running backend; leave it unset in Docker/production since the frontend is served from the same origin as the API.

## Run

1. Install dependencies for both workspaces:
   ```bash
   bun install
   ```

2. Start the backend API:
   ```bash
   bun run dev:backend
   ```

3. In a separate terminal, start the frontend dev server:
   ```bash
   bun run dev:frontend
   ```

## Create Users

Add users directly to the database with the admin script:

```bash
bun run user:add alice secret
```

The script uses `DATABASE_URL`, hashes the password with Bun's password API, and inserts the user into the `users` table.

Users are created with `active = true` and `role = user` by default. Pass `--inactive` to create the account disabled from the start, or `--admin` to grant it access to the management console's admin API:

```bash
bun run user:add alice secret --inactive
bun run user:add alice secret --admin
```

To enable or disable an existing user:

```bash
bun run user:set-active alice false
bun run user:set-active alice true
```

Disabling a user revokes all of their refresh tokens and clears the cached auth entry. Disabled users receive `403 Account disabled` from login and refresh attempts.

Existing bcrypt password hashes remain valid during login because Bun automatically detects the stored hash format. When a bcrypt user logs in successfully, the service upgrades the stored hash to Argon2.

Changing a password requires the current password and a valid access token. After a successful password change, all of the user's refresh tokens are revoked so any active sessions must log in again.

## API

### Login

`POST /auth/login`

Body:
```json
{ "username": "alice", "password": "secret", "audience": "calendar" }
```

`audience` is optional and names the app the session is for (`calendar` or `tracker`). With it, the access token's `aud` is just that app and the login is refused with `403` if the user's scopes do not include it; the refresh token remembers the app, so every refreshed token keeps the same `aud`. Without it, `aud` lists every app the user's scopes allow.

Returns `403 Account disabled` if the user exists but is not active, and `429` with a `Retry-After` header after too many failed attempts (see [Throttling and audit log](#throttling-and-audit-log)).

### Access Token

Access tokens returned by `/auth/login` and `/auth/refresh` are ES256 JWTs. The header carries the `kid` used to look up the right key in the [JWKS](#jwks) response, and the payload embeds the user's `role` and per-app `scopes` alongside the standard claims:

Header:
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "PHHBl06NKNzZl_uwM4NVsWUND20osHGDha3JmU6E7mw"
}
```

Payload:
```json
{
  "sub": "8f14e45f-ceea-467e-bb92-42f2c1e6b6d1",
  "username": "alice",
  "role": "admin",
  "scopes": { "calendar": true, "tracker": false },
  "type": "access",
  "iss": "https://auth.legacy-group.tech",
  "aud": ["calendar"],
  "iat": 1783774116,
  "exp": 1783775016
}
```

- `sub` — the user's id (UUID)
- `role` — `"admin"` or `"user"`
- `scopes` — the same `{ calendar, tracker }` object exposed by the [Admin API](#admin-api), snapshotted at the time the token was issued
- `type` — always `"access"` (refresh tokens, which are separate HS256 JWTs, use `"refresh"` and add a `jti`)
- `iss` — `JWT_ISSUER`
- `aud` — the apps this token is for: the login's `audience`, or every app in `scopes` that is `true`. Omitted when that is none (an account that only uses this service's console). An app must reject tokens whose `aud` does not include it.
- `iat` / `exp` — issued-at and expiry, in Unix seconds (`exp - iat` equals `ACCESS_TOKEN_TTL_SECONDS`)

`role` and `scopes` reflect the user's state at login/refresh time — they are not updated until the token is refreshed, so a role or scope change made via the Admin API takes effect on the affected user's next token refresh (or next login), not immediately. Downstream apps can either trust these claims after verifying the token against the [JWKS](#jwks) key, or call the Admin API directly for up-to-the-second values.

**Decision on freshness (needs a yes from whoever owns the roadmap).** A role or scope change reaches a user's tokens at their next refresh, so for up to `ACCESS_TOKEN_TTL_SECONDS` (15 minutes) a revoked permission still works at the resource servers. Refreshing always re-reads the user, and ending an account's sessions (disable, delete, password change) is immediate for refresh tokens and for the OpenID Provider. Instant revocation of an *access token* would need a `token_version` claim checked by every resource server, or an introspection endpoint; neither is built. If 15 minutes is too long, lower `ACCESS_TOKEN_TTL_SECONDS` first: it is the cheap lever.

### Refresh

`POST /auth/refresh`

Body:
```json
{ "refresh_token": "..." }
```

Refreshing revokes the refresh token and returns a new one. A rotated token can still be refreshed for `REFRESH_REUSE_GRACE_SECONDS` (default `30`), so a client that refreshes twice in parallel, or retries after losing the response, is not signed out; after that it gets `401`. Logout, password changes and disabling an account revoke tokens outright, and the grace period does not apply to them. Scopes are re-read on every refresh, so a session opened for an app whose scope has since been removed gets `403` and is revoked.

Returns `403 Account disabled` if the refresh token belongs to an inactive user.

### Logout

`POST /auth/logout`

Body:
```json
{ "refresh_token": "..." }
```

### Change Password

`POST /auth/change-password`

Headers:
```http
Authorization: Bearer <access_token>
```

Body:
```json
{ "current_password": "old-secret", "new_password": "new-secret" }
```

Returns `401 Invalid access token` if the bearer token is missing or invalid, `401 Current password is invalid` if the current password does not match, and `403 Account disabled` if the account is inactive.

On success, the response is:

```json
{ "success": true }
```

### Profile Picture

`POST /auth/profile-picture`

Headers:
```http
Authorization: Bearer <access_token>
```

Body: `multipart/form-data` with a `file` field containing a JPEG, PNG, WebP, or GIF image.

Non-GIF images are resized to 256x256 (cropped to fit) and re-encoded as JPEG at quality 82. GIFs are resized to 256x256 and kept as GIF, preserving animation. The stored file replaces any previous profile picture for the user, including one saved in a different format.

Returns `413` if the upload exceeds `AVATAR_MAX_UPLOAD_BYTES`, and `400` if the file is missing, not a supported image format, or corrupted.

On success:
```json
{ "success": true, "content_type": "image/jpeg" }
```

`GET /auth/profile-picture/:userId`

Returns the stored image bytes with the appropriate `Content-Type` (`image/jpeg` or `image/gif`). Returns `404` if the user has no profile picture stored, and `400` if `userId` is not a valid UUID. This endpoint does not require authentication.

Profile pictures are stored on the filesystem under `AVATAR_STORAGE_DIR`, named `<user_id>.jpg` or `<user_id>.gif`. In Docker, mount a volume at `/app/data/avatars` (the default `AVATAR_STORAGE_DIR`) so uploads survive container restarts.

### JWKS

`GET /.well-known/jwks.json`

Returns the public key used to verify access token signatures. External services can fetch this endpoint to validate JWTs without sharing any secret.

Example response:
```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "z20qlP...",
      "y": "byEn7E...",
      "use": "sig",
      "alg": "ES256",
      "kid": "PHHBl06NKNzZl_uwM4NVsWUND20osHGDha3JmU6E7mw"
    }
  ]
}
```

To generate a stable key pair for production:
```bash
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt > ec-private.pem
```

Set `JWT_PRIVATE_KEY` to the contents of `ec-private.pem`. In a `.env` file, newlines can be stored as `\n`:
```bash
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIGH...\n-----END PRIVATE KEY-----"
```

### Android apps

`GET /.well-known/assetlinks.json`

Passkeys belong to this service's host (the WebAuthn RP ID). A browser on that host can use them directly, but Android's passkey providers (Google Password Manager and others) only let a native app use them once this file names the app's package and signing certificate. Set `PASSKEY_ANDROID_APPS` to one entry per certificate that signs a build you want passkeys in:

```bash
PASSKEY_ANDROID_APPS=com.legacy.legacytracker:AB:CD:...:EF
```

`keytool -list -v -keystore <keystore>` (or `apksigner verify --print-certs app.apk`) prints the SHA-256 fingerprint. The file must be served over HTTPS at the RP ID host with no redirect.

### Admin API

All endpoints below require `Authorization: Bearer <access_token>` for a user with `role: "admin"` (create one with `bun run user:add ... --admin`), and return `403 Admin role required` otherwise.

- `GET /admin/users?page=&pageSize=&q=&role=` — paginated user list. `q` matches username, `role` filters to `admin` or `user`.
- `POST /admin/users` — create a user: `{ username, password, role?, active? }`.
- `GET /admin/users/:id` — fetch a single user.
- `PATCH /admin/users/:id` — update a user: any of `{ username, role, active, password, scopes: { calendar, tracker } }`. Setting `password` revokes all of that user's refresh tokens. Setting `active: false` also revokes all sessions.
- `POST /admin/users/:id/avatar` — `multipart/form-data` with a `file` field, same rules as `POST /auth/profile-picture` but on behalf of another user.

Users carry a `role` (`admin` | `user`), an `active` flag, and a `scopes` object (`{ calendar, tracker }`) used to gate access to other internal apps. The auth service puts only the apps a user has a scope for in the token's `aud`; each app must still check `aud` (or `scopes`) itself. Both `role` and `scopes` are embedded in the [access token](#access-token) at login/refresh time, so downstream apps can read them straight off the verified JWT instead of calling the admin API, at the cost of the values being only as fresh as the user's last token refresh.

### Throttling and audit log

Failed password and passkey sign-ins are counted per username and per client IP in memory (so they reset on restart). After `LOGIN_MAX_FAILURES` failures for a username within `LOGIN_FAILURE_WINDOW_SECONDS` (or five times that many from one IP), `/auth/login` and `/auth/change-password` answer `429` with `Retry-After` until the window ends. Passkey sign-in carries no username, so it is throttled per IP only. A successful sign-in clears its username's count.

Per-IP counting needs the real client address. Behind a reverse proxy (or Docker's published port) the socket address is the proxy's, so set `TRUST_PROXY=true` there. Private and loopback addresses are never counted; when that is all that is known, only the per-username limit applies.

Sign-ins, failed refreshes, password changes, passkey registrations and deletions, and admin changes to users are written to the `auth_events` table (`event`, `success`, `user_id`, `username`, `actor_id` for admin actions, `ip`, `user_agent`, `detail`, `created_at`). Passwords, secrets, codes and tokens are never recorded. The OpenID Provider writes `oidc.login`, `oidc.consent`, `oidc.authorize`, `oidc.code.issued`, `oidc.token.issued`, `oidc.refresh.reuse`, `oidc.logout` and `oidc.backchannel`, and client changes are `admin_oidc_client_*`.

Rows older than `AUDIT_RETENTION_DAYS` (default 180) are deleted once a day. Admins can read the log with `GET /admin/audit-events` (newest first; filters `event`, `success`, `userId`, `username` (case-insensitive), `since` (inclusive), `until` (exclusive); `page`, `pageSize` up to 200).

**Single replica.** Failure counters, passkey challenges and the user cache are held in memory, so they reset on restart and are not shared between replicas: with two replicas every limit doubles and a passkey challenge issued by one cannot be verified by the other. Run one container, or put these in Postgres first. Everything the OpenID Provider keeps (sessions, grants, tokens, clients, retry queue) is in Postgres and survives a restart.

A rotated legacy refresh token can still be refreshed for `REFRESH_REUSE_GRACE_SECONDS`; presenting one *after* that revokes every token of its family (the chain started by one login) and is recorded as `refresh_reuse`. A token replayed *inside* the grace period still yields a working session; set the grace to `0` once clients refresh one at a time to close that window.

## OpenID Provider

Legacy Auth is an OpenID Provider built on [`node-oidc-provider`](https://github.com/panva/node-oidc-provider) (pinned to an exact version). Apps send the browser here to sign in, the browser keeps one session cookie for this service, and so signing in to one app signs the user in to the others, and signing out of one signs them out of all. It runs beside the old `/auth/login`, which keeps working.

| Endpoint | |
|---|---|
| `GET /.well-known/openid-configuration` | discovery |
| `GET /authorize` | start a sign-in (Authorization Code + PKCE) |
| `POST /token` | `authorization_code` and `refresh_token` grants; `client_secret_basic` for confidential clients, `none` for public ones |
| `GET /userinfo` | `sub`, `preferred_username`, `role` (see the note below) |
| `GET`/`POST /logout` | RP-initiated logout |
| `GET /.well-known/jwks.json` | the key set, **unchanged**: tokens from the OP are signed with the key the legacy endpoints already use |

### For an app that signs users in

Register a client (see [Clients](#clients)), then:

1. **Send the browser to `/authorize`** with: `response_type=code`, `client_id`, `redirect_uri` (exactly as registered, and always sent; there is no default), `scope`, `resource` (`urn:legacy:calendar` or `urn:legacy:tracker`, the app whose API you will call), `code_challenge` + `code_challenge_method=S256` (no other method, no PKCE-less request), `state`, `nonce` (required whenever `openid` is requested), and `prompt=consent` **if you ask for `offline_access`**. OIDC Core drops `offline_access` without it, and the library has no switch to change that. The "consent" is automatic and invisible: users are never shown a consent screen, and with a session they are not shown a login form either. Add `prompt=none` for a silent check (you get `login_required` instead of a form; a native app, i.e. a client redirected to a custom scheme, always gets `interaction_required` because the provider puts native clients through its consent step, so the mobile app must open the browser), `prompt=login` or `max_age` to force a fresh sign-in, `login_hint` to pre-fill the username.
2. **Exchange the code at `/token`** within 60 seconds, once, with the same `redirect_uri` and the `code_verifier`. Redeeming a code twice fails and revokes what the first redemption produced.
3. **Verify** the ID token (`iss`, `aud` = your `client_id`, `nonce`, signature against the JWKS) and keep the tokens server-side.
4. **Refresh** with the refresh token. Each refresh returns a new refresh token; the old one is dead. Presenting an old one again revokes the whole grant, **so refresh one request at a time** (a single-flight lock per session). There is no grace window here: two parallel refreshes of one token means one wins and the other fails.
5. **Sign out** by redirecting to `/logout?id_token_hint=…&post_logout_redirect_uri=…&state=…` (the redirect URI must be registered), and expose a **back-channel logout endpoint** (below).

Scopes: `openid`, `profile`, `offline_access`, `admin` (admins only), and per app `calendar.read`, `calendar.write`, `tracker.read`, `tracker.write`. A user's boolean app scope grants that app's read and write scopes together today; they are separate scopes so they can be split later (`entitledResourceScopes` in `backend/src/oidc/scopes.ts` is the one place to change). A request the signed-in user may not make (no scope for the app, `admin` without an admin account, a turned-off account) stops on a **no-access page** at the OP, the OP's version of the legacy `403`: it names the account and the app, and offers **Use another account** (the same authorization request again with `prompt=login`, so the app gets its code if the other account may sign in) and **Back to the app** (your redirect URI gets `error=access_denied`, with the reason in `error_description`). Apps therefore need no screen of their own for a missing scope, only a fallback for `access_denied` and for the errors of `prompt=none`, which never shows the page. A client only gets the scopes it is registered for.

**Access token** (JWT, header `typ: at+jwt`, ES256, `kid` as in the JWKS) for the resource it was asked for:

```json
{ "iss": "https://auth.legacy-group.tech", "aud": "calendar", "sub": "8f14e45f-…", "client_id": "calendar-web",
  "scope": "calendar.read calendar.write", "sid": "…", "jti": "…", "iat": 1783774116, "exp": 1783775016,
  "type": "access", "username": "alice", "role": "admin", "scopes": { "calendar": true, "tracker": false } }
```

`type` and `scopes` are the legacy claims the calendar and tracker check today, kept so they need no change to accept these tokens. `aud` is the plain app name they already pin, not the resource indicator. Each app must still check `iss`, `aud`, and a scope. Role and scopes are re-read from the user every time a token is issued, refreshes included, and a refresh fails with `invalid_grant` once the user has lost the app's scope or was disabled.

**ID token**: `iss`, `aud` (the client), `sub`, `nonce`, `auth_time`, `sid`, `acr` (`urn:legacy:loa:1`) and `amr` (`["pwd"]` for a password, `["webauthn"]` for a passkey), so a policy can require passkeys later. No `role`, no `scopes`.

**Differences from what the issue sketched**, each forced by the library or a deliberate tightening:

- Resource indicators must be absolute URIs (RFC 8707), so clients ask for `urn:legacy:calendar`; the token's `aud` is still `calendar`.
- `/userinfo` only accepts a token that is *not* tied to a resource (the library refuses an access token that has an `aud` there). The claims it returns are in the access token you already have; the endpoint is for a token requested without `resource`.
- The access token's `scope` lists the scopes of its resource only (`calendar.read calendar.write`), not `openid profile`.
- `at_hash` is not in ID tokens from the token endpoint: OIDC Core makes it optional in the code flow.
- `sid` is per session *and per client*, so one app's logout token cannot be taken for another's; every client's tokens carry one, back-channel or not.
- There is no refresh grace window at the OP (see step 4); the legacy `/auth/refresh` keeps its own.
- `nonce` and `redirect_uri` are required where OIDC and OAuth make them optional.

### Browser session

`__Host-legacy_session` (just `legacy_session` when `JWT_ISSUER` is not https): `Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`, signed. It is first issued when the user signs in, so there is nothing to plant beforehand, and signing in again rotates it. If someone signs in on a browser that already has a session for a different user, that session is ended first (everywhere), then the new user is signed in. A session ends after 14 days without activity or 30 days after sign-in; a sign-in, an `/authorize`, or a refresh token being used all count as activity. Sessions are rows in `oidc_sessions` (user, `auth_time`, `amr`, address, user agent, `last_seen_at`).

### Logout

`/logout?id_token_hint=…` shows a page that submits itself (the app already chose to sign out) and ends the session, every app's refresh tokens and every app's grant; without a hint it asks first. It only ever redirects to a registered `post_logout_redirect_uri`. Every app the browser was signed in to is sent a **back-channel logout**: a `POST` of `logout_token=<JWT>` (form-encoded) to its `backchannel_logout_uri`. The app must verify it (ES256 against the JWKS; `iss`; `aud` = its `client_id`; `typ` header `logout+jwt`; `events` holds `http://schemas.openid.net/event/backchannel-logout`; there is no `nonce`), delete the session whose `sid` matches (`sub` identifies the user) and answer `200` or `204`. A delivery that fails is retried after 5 s, 30 s, 2 min, 10 min and 1 h, then given up, and every attempt is in the audit log; retries are in the database, so a restart does not lose them. A slow app never delays the user's logout by more than a few seconds.

Disabling an account, deleting it, or changing its password (by the user or an admin) does the same for every session it has. Removing one app scope ends only that app's tokens: the user stays signed in for the others.

### Clients

Registered relying parties live in `oidc_clients` and are managed with the admin API (admin access token; responses are never cached; secrets appear only in the response that creates or rotates them, and only a SHA-256 hash is stored):

- `GET /admin/oidc/clients`, `GET /admin/oidc/clients/:id`
- `POST /admin/oidc/clients` — `{ client_id, name, is_public, redirect_uris, post_logout_redirect_uris?, backchannel_logout_uri?, allowed_scopes, disabled? }`; a confidential client's `client_secret` is in the `201`.
- `PATCH /admin/oidc/clients/:id` — any of `name`, `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_uri`, `allowed_scopes`. `is_public` cannot change; unknown fields are refused so a typo is not silently ignored.
- `POST /admin/oidc/clients/:id/rotate-secret` — `{ grace_seconds? }` (0–30 days; default `OIDC_SECRET_ROTATION_GRACE_SECONDS`, `0` revokes the old secret at once). Rotating signs nobody out: refresh tokens belong to the client, not its secret.
- `POST /admin/oidc/clients/:id/disable` and `/enable` — a disabled client gets `invalid_client` everywhere, refreshes included.

Redirect URIs are matched exactly (no wildcards, no fragments, no credentials), must be `https` (or `http` on `localhost`), and a custom scheme such as `com.legacy.legacytracker:/oauth2redirect` is only allowed for a public (native) client. There is no client UI yet; the admin API is enough.

The four clients from the issue (`calendar-web`, `tracker-web`, `tracker-mobile`, `auth-console`) are inserted at startup, **disabled**, and the confidential ones have **no secret**, so deploying this changes nothing for anyone. To bring one into service: `POST …/rotate-secret`, put the returned secret in that app's configuration, then `POST …/enable`. Their post-logout and back-channel URIs are defaults (`https://<host>/` and `https://<host>/auth/backchannel-logout`): `PATCH` them to match the app.

### Operating it

- **Shutdown:** on `SIGTERM`/`SIGINT` (what `docker stop` sends) the server stops accepting requests, lets the OP finish what it is doing and removes its socket.
- **Rollback:** `OIDC_ENABLED=false` and restart. Clients, sessions and grants stay in Postgres, so switching it back on resumes where it left off. If the OP *fails to start* the error is logged and the rest of the service carries on; its paths answer `503`.
- **How it runs:** `oidc-provider` is a Node `http` handler, so it runs in this process on a private Unix socket (a `0700` temp directory, no TCP port) behind a small proxy in the Bun server. The proxy states the client address and scheme itself (anything a client sent for those is discarded), adds `X-Frame-Options: DENY`, a `frame-ancestors 'none'` CSP, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and throttles failed `/token` and malformed `/authorize` requests per client address. Failed password and passkey attempts at the sign-in page share their counts with `/auth/login`.
- **The library does not support Bun.** It prints `Unsupported runtime` at startup. The suite runs on Bun and exercises every flow, and the version is pinned, so an upgrade is a deliberate act that the tests check. Its own guard against calling internal addresses hooks undici, which Bun does not use, so it silently does nothing here; back-channel URIs are therefore checked at registration and again just before each delivery (`oidc/net-safety.ts`), and in production they may not point at localhost or a private network.
- **Two patches** to the library's `Client` (`provider.ts`): client secrets are compared as hashes with a rotation grace, and `sid` is on every token. A library upgrade that renames either fails the tests rather than the login.
- **Tables:** `oidc_clients`, `oidc_payloads` (grants, codes, refresh tokens, interactions), `oidc_sessions`, `oidc_backchannel_retries`; expired rows are purged hourly. Bearer values are never stored: rows are keyed by a hash and the token is stripped from the stored payload, so a leaked table or backup cannot be replayed. Include these tables in backups.
- **Not run here:** the OpenID Foundation conformance suite needs a deployed instance reachable from the internet; run its Basic OP profile against the real deployment before relying on it.

## Retiring password login

`POST /auth/login` and the passkey login endpoints (`/auth/passkey/login-options`, `/auth/passkey/login-verify`) are **deprecated**: every response carries `Deprecation: true` and a `Link … rel="successor-version"` to the discovery document. They keep honouring `audience`. The order the issue lays down:

1. Deploy the OP with its clients disabled (this release).
2. Each app registers its client and moves to the OP behind a flag; apps that still use password login keep sending `audience`.
3. Set `REQUIRE_AUDIENCE=true` once every remaining client sends it.
4. After one release cycle with no `/auth/login` traffic, delete those endpoints and drop the legacy `scopes` object from tokens.

Removing them breaks any mobile build that has not updated, and the tracker has no minimum-version enforcement yet: add one first, or keep password login for old builds with `REQUIRE_AUDIENCE=true`.

## Tests

The suite (`bun run test`) needs a throwaway Postgres server that can `CREATE DATABASE`; each run makes its own database and drops it. It must never be pointed at production.

```bash
docker run --rm -p 54329:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:54329/postgres bun run test
```

It starts the real OpenID Provider and drives it over HTTP with a browser emulator (cookies, redirects, form posts), a software WebAuthn authenticator and stub back-channel endpoints, and it covers the issue's adversarial cases: code replay, `redirect_uri` substitution, PKCE downgrade, session fixation, login CSRF, cross-app token replay, refresh reuse, secrets at rest, rate limits and header hardening.

## Swagger

Open the interactive docs at:

`GET /docs`

The raw OpenAPI document is available at:

`GET /openapi.json`

## Frontend

The console (`frontend/`) is a Vue 3 + Vite SPA. It talks to the backend over the API described above, using `VITE_API_URL` (empty/same-origin by default) as the base URL. Non-admin users only see the Settings page (avatar, username, password); the Users section requires the `admin` role.

## Docker

```bash
docker build -t legacy-auth .
docker run -p 4000:4000 --env-file backend/.env legacy-auth
```

The Dockerfile builds the frontend in one stage and copies the static output into the backend runtime image (`FRONTEND_DIST_DIR=/app/frontend/dist`), so the container serves both the API and the console on port `4000` — there's nothing else to expose or run separately. Profile picture uploads are persisted via a volume at `/app/backend/data/avatars`.
