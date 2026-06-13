# Legacy Auth Service

A lightweight Bun-based authentication microservice for the Legacy ecosystem.

## Features

- `POST /auth/login` to authenticate users
- `POST /auth/refresh` to refresh access tokens
- `POST /auth/logout` to revoke refresh tokens
- Swagger UI at `GET /docs`
- OpenAPI spec at `GET /openapi.json`
- JWT access tokens (ES256) + refresh tokens (HS256)
- JWKS endpoint at `GET /.well-known/jwks.json` for public key discovery
- in-memory username/password cache
- PostgreSQL backed refresh token revocation
- bcrypt password hashing with 12 rounds

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
- `BCRYPT_SALT_ROUNDS` (default: `12`)

## Run

1. Install dependencies:
   ```bash
   bun install
   ```

2. Start the service:
   ```bash
   bun run src/index.ts
   ```

## Create Users

Add users directly to the database with the admin script:

```bash
bun run user:add alice secret
```

The script uses `DATABASE_URL`, hashes the password with bcrypt, and inserts the user into the `users` table.

## API

### Login

`POST /auth/login`

Body:
```json
{ "username": "alice", "password": "secret" }
```

### Refresh

`POST /auth/refresh`

Body:
```json
{ "refresh_token": "..." }
```

### Logout

`POST /auth/logout`

Body:
```json
{ "refresh_token": "..." }
```

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

## Swagger

Open the interactive docs at:

`GET /docs`

The raw OpenAPI document is available at:

`GET /openapi.json`
