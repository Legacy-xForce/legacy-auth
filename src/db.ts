import { SQL } from "bun";
import { UserRecord, RefreshTokenRecord } from "./types.ts";
import { config } from "./config.ts";
import { createHash } from "crypto";

const sql = new SQL(config.dbUrl);

export async function initDatabase() {
  const bootstrapSql = new SQL(config.dbUrl);

  try {
    await bootstrapSql`CREATE EXTENSION IF NOT EXISTS pgcrypto;`;

    await bootstrapSql`
      CREATE TABLE IF NOT EXISTS users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        username text NOT NULL UNIQUE,
        password_hash text NOT NULL,
        active boolean NOT NULL DEFAULT true,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
    `;

    await bootstrapSql`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;
    `;

    await bootstrapSql`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        jti text NOT NULL UNIQUE,
        token_hash text NOT NULL,
        expires_at timestamptz NOT NULL,
        revoked_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now()
      );
    `;
  } finally {
    await bootstrapSql.close({ timeout: 0 });
  }
}

export async function findUserByUsername(username: string): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    SELECT id, username, password_hash, active, created_at, updated_at
    FROM users
    WHERE username = ${username}
    LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function findUserActiveByUsername(username: string): Promise<Pick<UserRecord, "id" | "active"> | null> {
  const result = await sql<Pick<UserRecord, "id" | "active">[]>`
    SELECT id, active FROM users WHERE username = ${username} LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function findUserById(id: string): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    SELECT id, username, password_hash, active, created_at, updated_at
    FROM users
    WHERE id = ${id}
    LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function createUser(username: string, password: string): Promise<UserRecord> {
  return createUserWithActive(username, password, true);
}

export async function createUserWithActive(username: string, password: string, active: boolean): Promise<UserRecord> {
  const passwordHash = await Bun.password.hash(password);
  const result = await sql<UserRecord[]>`
    INSERT INTO users (username, password_hash, active)
    VALUES (${username}, ${passwordHash}, ${active})
    RETURNING id, username, password_hash, active, created_at, updated_at;
  `;
  return result[0];
}

export async function upsertUserWithPasswordHash(username: string, passwordHash: string, active: boolean): Promise<UserRecord> {
  const result = await sql<UserRecord[]>`
    INSERT INTO users (username, password_hash, active)
    VALUES (${username}, ${passwordHash}, ${active})
    ON CONFLICT (username) DO UPDATE SET
      password_hash = EXCLUDED.password_hash,
      active = EXCLUDED.active,
      updated_at = now()
    RETURNING id, username, password_hash, active, created_at, updated_at;
  `;
  return result[0];
}

export async function updateUserPasswordHash(userId: string, passwordHash: string): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    UPDATE users
    SET password_hash = ${passwordHash},
        updated_at = now()
    WHERE id = ${userId}
    RETURNING id, username, password_hash, active, created_at, updated_at;
  `;
  return result[0] ?? null;
}

export async function updateUserActive(userId: string, active: boolean): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    UPDATE users
    SET active = ${active},
        updated_at = now()
    WHERE id = ${userId}
    RETURNING id, username, password_hash, active, created_at, updated_at;
  `;
  return result[0] ?? null;
}

export async function listUsers(): Promise<Pick<UserRecord, "id" | "username">[]> {
  return sql<Pick<UserRecord, "id" | "username">[]>`
    SELECT id, username
    FROM users
    ORDER BY username;
  `;
}

export async function deleteUserByUsername(username: string): Promise<void> {
  await sql`
    DELETE FROM users
    WHERE username = ${username};
  `;
}

export async function saveRefreshToken(userId: string, jti: string, token: string, expiresAt: Date): Promise<RefreshTokenRecord> {
  const tokenHash = hashToken(token);
  const result = await sql<RefreshTokenRecord[]>`
    INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at)
    VALUES (${userId}, ${jti}, ${tokenHash}, ${expiresAt.toISOString()})
    RETURNING id, user_id, jti, token_hash, expires_at, revoked_at, created_at;
  `;
  return result[0];
}

export async function findRefreshTokenByJti(jti: string): Promise<RefreshTokenRecord | null> {
  const result = await sql<RefreshTokenRecord[]>`
    SELECT id, user_id, jti, token_hash, expires_at, revoked_at, created_at
    FROM refresh_tokens
    WHERE jti = ${jti}
    LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function revokeRefreshToken(jti: string): Promise<void> {
  await sql`
    UPDATE refresh_tokens SET revoked_at = now() WHERE jti = ${jti};
  `;
}

export async function revokeAllRefreshTokensForUser(userId: string): Promise<void> {
  await sql`
    UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ${userId};
  `;
}

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function verifyRefreshTokenHash(token: string, tokenHash: string): Promise<boolean> {
  return hashToken(token) === tokenHash;
}
