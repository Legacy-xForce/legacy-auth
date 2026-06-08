# Legacy Auth Service

A lightweight Bun-based authentication microservice for the Legacy ecosystem.

## Features

- `POST /auth/login` to authenticate users
- `POST /auth/refresh` to refresh access tokens
- `POST /auth/logout` to revoke refresh tokens
- Swagger UI at `GET /docs`
- OpenAPI spec at `GET /openapi.json`
- JWT access + refresh tokens
- in-memory username/password cache
- PostgreSQL backed refresh token revocation
- bcrypt password hashing with 12 rounds

## Environment

Required environment variables:

- `DATABASE_URL` - Postgres connection string
- `JWT_SECRET` - secret for JWT signing

Optional environment variables:

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

## Swagger

Open the interactive docs at:

`GET /docs`

The raw OpenAPI document is available at:

`GET /openapi.json`
