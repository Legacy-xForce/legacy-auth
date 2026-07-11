import { SQL } from "bun";
import { UserRecord, RefreshTokenRecord, UserRole, UserScopes } from "./types.ts";
import { config } from "./config.ts";
import { createHash } from "crypto";

const sql = new SQL(config.dbUrl);

const USER_COLUMNS = "id, username, password_hash, role, active, scopes, created_at, updated_at";

const DEFAULT_SCOPES: UserScopes = { calendar: false, tracker: false };

function normalizeScopes(raw: unknown): UserScopes {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  return {
    calendar: Boolean((value as Partial<UserScopes> | null)?.calendar),
    tracker: Boolean((value as Partial<UserScopes> | null)?.tracker),
  };
}

function normalizeUser<T extends { scopes?: unknown } | null | undefined>(row: T): T {
  if (!row) return row;
  return { ...row, scopes: normalizeScopes(row.scopes) };
}

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
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user';
    `;

    await bootstrapSql`
      ALTER TABLE users
      DROP COLUMN IF EXISTS locked;
    `;

    await bootstrapSql`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS scopes jsonb NOT NULL DEFAULT '{}'::jsonb;
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
    SELECT ${sql.unsafe(USER_COLUMNS)}
    FROM users
    WHERE username = ${username}
    LIMIT 1;
  `;
  return normalizeUser(result[0]) ?? null;
}

export async function findUserActiveByUsername(username: string): Promise<Pick<UserRecord, "id" | "active"> | null> {
  const result = await sql<Pick<UserRecord, "id" | "active">[]>`
    SELECT id, active FROM users WHERE username = ${username} LIMIT 1;
  `;
  return result[0] ?? null;
}

export async function findUserById(id: string): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    SELECT ${sql.unsafe(USER_COLUMNS)}
    FROM users
    WHERE id = ${id}
    LIMIT 1;
  `;
  return normalizeUser(result[0]) ?? null;
}

export async function createUser(username: string, password: string): Promise<UserRecord> {
  return createUserWithActive(username, password, true);
}

export async function createUserWithActive(
  username: string,
  password: string,
  active: boolean,
  options: { role?: UserRole } = {}
): Promise<UserRecord> {
  const passwordHash = await Bun.password.hash(password);
  const role = options.role ?? "user";
  const result = await sql<UserRecord[]>`
    INSERT INTO users (username, password_hash, active, role)
    VALUES (${username}, ${passwordHash}, ${active}, ${role})
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]);
}

export async function upsertUserWithPasswordHash(username: string, passwordHash: string, active: boolean): Promise<UserRecord> {
  const result = await sql<UserRecord[]>`
    INSERT INTO users (username, password_hash, active)
    VALUES (${username}, ${passwordHash}, ${active})
    ON CONFLICT (username) DO UPDATE SET
      password_hash = EXCLUDED.password_hash,
      active = EXCLUDED.active,
      updated_at = now()
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]);
}

export async function updateUserPasswordHash(userId: string, passwordHash: string): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    UPDATE users
    SET password_hash = ${passwordHash},
        updated_at = now()
    WHERE id = ${userId}
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]) ?? null;
}

export async function updateUserActive(userId: string, active: boolean): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    UPDATE users
    SET active = ${active},
        updated_at = now()
    WHERE id = ${userId}
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]) ?? null;
}

export type UserProfileUpdate = {
  username?: string;
  role?: UserRole;
  active?: boolean;
};

export async function updateUserProfile(userId: string, update: UserProfileUpdate): Promise<UserRecord | null> {
  const existing = await findUserById(userId);
  if (!existing) return null;

  const username = update.username ?? existing.username;
  const role = update.role ?? existing.role;
  const active = update.active === undefined ? existing.active : update.active;

  const result = await sql<UserRecord[]>`
    UPDATE users
    SET username = ${username},
        role = ${role},
        active = ${active},
        updated_at = now()
    WHERE id = ${userId}
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]) ?? null;
}

export async function updateUserScopes(userId: string, scopes: UserScopes): Promise<UserRecord | null> {
  const result = await sql<UserRecord[]>`
    UPDATE users
    SET scopes = ${JSON.stringify(scopes)}::jsonb,
        updated_at = now()
    WHERE id = ${userId}
    RETURNING ${sql.unsafe(USER_COLUMNS)};
  `;
  return normalizeUser(result[0]) ?? null;
}

export type UserListFilters = {
  search?: string;
  role?: UserRole;
  page: number;
  pageSize: number;
};

export async function listUsersPaginated(filters: UserListFilters): Promise<{ items: UserRecord[]; total: number }> {
  const search = filters.search?.trim();
  const searchPattern = search ? `%${search}%` : null;
  const offset = (filters.page - 1) * filters.pageSize;

  const items = await sql<UserRecord[]>`
    SELECT ${sql.unsafe(USER_COLUMNS)}
    FROM users
    WHERE (${searchPattern}::text IS NULL OR username ILIKE ${searchPattern})
      AND (${filters.role ?? null}::text IS NULL OR role = ${filters.role ?? null})
    ORDER BY lower(username) ASC
    LIMIT ${filters.pageSize} OFFSET ${offset};
  `;

  const countResult = await sql<{ count: string }[]>`
    SELECT COUNT(*)::text AS count
    FROM users
    WHERE (${searchPattern}::text IS NULL OR username ILIKE ${searchPattern})
      AND (${filters.role ?? null}::text IS NULL OR role = ${filters.role ?? null});
  `;

  return {
    items: items.map((item) => normalizeUser(item)),
    total: Number(countResult[0]?.count ?? 0),
  };
}

export async function deleteUserByUsername(username: string): Promise<void> {
  await sql`
    DELETE FROM users
    WHERE username = ${username};
  `;
}

export async function deleteUserById(id: string): Promise<boolean> {
  const result = await sql`
    DELETE FROM users
    WHERE id = ${id}
    RETURNING id;
  `;
  return result.length > 0;
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
