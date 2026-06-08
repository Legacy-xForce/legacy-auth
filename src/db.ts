import { SQL } from "bun";
import { UserRecord, RefreshTokenRecord } from "./types.ts";
import { config } from "./config.ts";
import { createHash } from "crypto";

const db = new SQL(config.dbUrl);

export async function initDatabase() {
  await db`CREATE EXTENSION IF NOT EXISTS pgcrypto;`;

  await db`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      username text NOT NULL UNIQUE,
      password_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `;

  await db`
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
}

export async function findUserByUsername(username: string): Promise<UserRecord | null> {
  const result = await db<UserRecord[]>`
    SELECT * FROM users WHERE username = ${username} LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function findUserById(id: string): Promise<UserRecord | null> {
  const result = await db<UserRecord[]>`
    SELECT * FROM users WHERE id = ${id} LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function createUser(username: string, passwordHash: string): Promise<UserRecord> {
  const result = await db<UserRecord[]>`
    INSERT INTO users (username, password_hash)
    VALUES (${username}, ${passwordHash})
    RETURNING *;
  `;
  return result[0];
}

export async function saveRefreshToken(userId: string, jti: string, token: string, expiresAt: Date): Promise<RefreshTokenRecord> {
  const tokenHash = hashToken(token);
  const result = await db<RefreshTokenRecord[]>`
    INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at)
    VALUES (${userId}, ${jti}, ${tokenHash}, ${expiresAt.toISOString()})
    RETURNING *;
  `;
  return result[0];
}

export async function findRefreshTokenByJti(jti: string): Promise<RefreshTokenRecord | null> {
  const result = await db<RefreshTokenRecord[]>`
    SELECT * FROM refresh_tokens WHERE jti = ${jti} LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function revokeRefreshToken(jti: string): Promise<void> {
  await db`
    UPDATE refresh_tokens SET revoked_at = now() WHERE jti = ${jti};
  `;
}

export async function revokeAllRefreshTokensForUser(userId: string): Promise<void> {
  await db`
    UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ${userId};
  `;
}

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function verifyRefreshTokenHash(token: string, tokenHash: string): Promise<boolean> {
  return hashToken(token) === tokenHash;
}
