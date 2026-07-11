# Legacy Auth

A lightweight Bun-based authentication service for the Legacy ecosystem, plus a Vue 3 management console for administering users.

This is a monorepo (Bun workspaces):

- [`backend/`](backend) — the auth API (Bun, PostgreSQL, JWT).
- [`frontend/`](frontend) — the Vue 3 + Vite management console.

In production (see [Docker](#docker)), the backend serves the built frontend as static files on the same port, so the whole app is a single deployable image.

## Features

- `POST /auth/login` to authenticate users
- `POST /auth/refresh` to refresh access tokens
- `POST /auth/logout` to revoke refresh tokens
- `POST /auth/change-password` to change the authenticated user's password
- `GET /auth/me` / `PATCH /auth/me` to read/update the authenticated user's own profile
- `POST /auth/profile-picture` to upload a profile picture (resized to 256x256, JPEG-compressed; GIFs stay animated)
- `GET /auth/profile-picture/:userId` to fetch a user's profile picture
- Admin user management: list/create/update users, roles, active/locked status, and per-app scopes (see [Admin API](#admin-api))
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
- `JWT_SECRET` - secret used to sign refresh tokens (HS256)
- `JWT_PRIVATE_KEY` - EC P-256 private key in PEM format used to sign access tokens (ES256). If unset, an ephemeral key is generated at startup — tokens will be invalidated on restart.

Optional environment variables:

- `JWT_KEY_ID` - override the `kid` claim in access tokens and the JWKS response. Defaults to the RFC 7638 SHA-256 thumbprint of the public key.
- `PORT` (default: `4000`)
- `ACCESS_TOKEN_TTL_SECONDS` (default: `900`)
- `REFRESH_TOKEN_TTL_SECONDS` (default: `2592000`)
- `CACHE_TTL_MS` (default: `300000`)
- `AVATAR_STORAGE_DIR` - directory where profile picture files are stored on disk, relative to `backend/` (default: `./data/avatars`)
- `AVATAR_MAX_UPLOAD_BYTES` - maximum accepted profile picture upload size in bytes (default: `8388608`, i.e. 8 MiB)
- `FRONTEND_DIST_DIR` - directory of the built frontend to serve as static files, relative to `backend/` (default: `../frontend/dist`). If missing, the backend simply serves the API and returns `404` for unknown routes.

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

Disabling a user revokes all of their refresh tokens and clears the cached auth entry. Disabled users receive `403 Account disabled` from login and refresh attempts. Locked users (set via the admin API) receive `403 Account locked`.

Existing bcrypt password hashes remain valid during login because Bun automatically detects the stored hash format. When a bcrypt user logs in successfully, the service upgrades the stored hash to Argon2.

Changing a password requires the current password and a valid access token. After a successful password change, all of the user's refresh tokens are revoked so any active sessions must log in again.

## API

### Login

`POST /auth/login`

Body:
```json
{ "username": "alice", "password": "secret" }
```

Returns `403 Account disabled` if the user exists but is not active.

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
  "iat": 1783774116,
  "exp": 1783775016
}
```

- `sub` — the user's id (UUID)
- `role` — `"admin"` or `"user"`
- `scopes` — the same `{ calendar, tracker }` object exposed by the [Admin API](#admin-api), snapshotted at the time the token was issued
- `type` — always `"access"` (refresh tokens, which are separate HS256 JWTs, use `"refresh"` and add a `jti`)
- `iat` / `exp` — issued-at and expiry, in Unix seconds (`exp - iat` equals `ACCESS_TOKEN_TTL_SECONDS`)

`role` and `scopes` reflect the user's state at login/refresh time — they are not updated until the token is refreshed, so a role or scope change made via the Admin API takes effect on the affected user's next token refresh (or next login), not immediately. Downstream apps can either trust these claims after verifying the token against the [JWKS](#jwks) key, or call the Admin API directly for up-to-the-second values.

### Refresh

`POST /auth/refresh`

Body:
```json
{ "refresh_token": "..." }
```

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

### Admin API

All endpoints below require `Authorization: Bearer <access_token>` for a user with `role: "admin"` (create one with `bun run user:add ... --admin`), and return `403 Admin role required` otherwise.

- `GET /admin/users?page=&pageSize=&q=&role=` — paginated user list. `q` matches username, `role` filters to `admin` or `user`.
- `POST /admin/users` — create a user: `{ username, password, role?, active? }`.
- `GET /admin/users/:id` — fetch a single user.
- `PATCH /admin/users/:id` — update a user: any of `{ username, role, active, locked, password, scopes: { calendar, tracker } }`. Setting `password` revokes all of that user's refresh tokens. Setting `active: false` or `locked: true` also revokes all sessions.
- `POST /admin/users/:id/avatar` — `multipart/form-data` with a `file` field, same rules as `POST /auth/profile-picture` but on behalf of another user.

Users carry a `role` (`admin` | `user`), an `active`/`locked` status, and a `scopes` object (`{ calendar, tracker }`) used to gate access to other internal apps — the auth service itself doesn't enforce scopes. Both `role` and `scopes` are embedded in the [access token](#access-token) at login/refresh time, so downstream apps can read them straight off the verified JWT instead of calling the admin API, at the cost of the values being only as fresh as the user's last token refresh.

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
