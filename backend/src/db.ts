import { SQL } from "bun";
import { UserRecord, RefreshTokenRecord, PasskeyCredentialRecord, UserRole, UserScopes } from "./types.ts";
import { config } from "./config.ts";
import { initOidcSchema } from "./oidc/schema.ts";

import { createHash } from "crypto";

export const sql = new SQL(config.dbUrl);

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

    await bootstrapSql`
      ALTER TABLE refresh_tokens
      ADD COLUMN IF NOT EXISTS rotated_at timestamptz;
    `;

    // A login starts a family; every refresh token rotated from it joins it, so a
    // replayed token can take the whole chain down. Tokens from before this column
    // have no family and count as their own (see revokeRefreshFamily).
    await bootstrapSql`
      ALTER TABLE refresh_tokens
      ADD COLUMN IF NOT EXISTS family_id uuid;
    `;

    await bootstrapSql`
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id
      ON refresh_tokens(family_id);
    `;

    await bootstrapSql`
      CREATE TABLE IF NOT EXISTS passkey_credentials (
        id text PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key text NOT NULL,
        counter bigint NOT NULL DEFAULT 0,
        device_name text,
        created_at timestamptz NOT NULL DEFAULT now()
      );
    `;

    await bootstrapSql`
      CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id
      ON passkey_credentials(user_id);
    `;

    await bootstrapSql`
      CREATE TABLE IF NOT EXISTS auth_events (
        id bigserial PRIMARY KEY,
        event text NOT NULL,
        success boolean NOT NULL,
        user_id uuid REFERENCES users(id) ON DELETE SET NULL,
        username text,
        actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
        ip text,
        user_agent text,
        detail text,
        created_at timestamptz NOT NULL DEFAULT now()
      );
    `;

    await bootstrapSql`
      CREATE INDEX IF NOT EXISTS idx_auth_events_created_at
      ON auth_events(created_at);
    `;

    await bootstrapSql`
      CREATE INDEX IF NOT EXISTS idx_auth_events_user_id
      ON auth_events(user_id);
    `;

    await initOidcSchema(bootstrapSql);
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

/**
 * Stores a refresh token. A login passes no `familyId` and starts a new family;
 * a refresh passes the family of the token it rotates.
 */
export async function saveRefreshToken(userId: string, jti: string, token: string, expiresAt: Date, familyId?: string): Promise<RefreshTokenRecord> {
  const tokenHash = hashToken(token);
  const result = await sql<RefreshTokenRecord[]>`
    INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at, family_id)
    VALUES (${userId}, ${jti}, ${tokenHash}, ${expiresAt.toISOString()}, COALESCE(${familyId ?? null}::uuid, gen_random_uuid()))
    RETURNING id, user_id, jti, token_hash, expires_at, revoked_at, rotated_at, family_id, created_at;
  `;
  return result[0];
}

export async function findRefreshTokenByJti(jti: string): Promise<RefreshTokenRecord | null> {
  const result = await sql<RefreshTokenRecord[]>`
    SELECT id, user_id, jti, token_hash, expires_at, revoked_at, rotated_at, family_id, created_at
    FROM refresh_tokens
    WHERE jti = ${jti}
    LIMIT 1;
  `;
  return result[0] ?? null;
}

/**
 * Revokes a refresh token for rotation and says whether the caller may rotate
 * it: `"first"` when this call revoked it, `"grace"` when it was rotated less
 * than `graceSeconds` ago (parallel refreshes, or a retry after a lost
 * response), `null` otherwise. Explicit revocations clear `rotated_at`, so the
 * grace period never undoes a logout or password change.
 */
export async function claimRefreshToken(jti: string, graceSeconds: number): Promise<"first" | "grace" | null> {
  const claimed = await sql`
    UPDATE refresh_tokens SET revoked_at = now(), rotated_at = now()
    WHERE jti = ${jti} AND revoked_at IS NULL
    RETURNING id;
  `;
  if (claimed.length > 0) return "first";
  const recent = await sql`
    SELECT id FROM refresh_tokens
    WHERE jti = ${jti}
      AND rotated_at IS NOT NULL
      AND rotated_at > now() - make_interval(secs => ${graceSeconds})
    LIMIT 1;
  `;
  return recent.length > 0 ? "grace" : null;
}

/**
 * Revokes every token of a family, the one in hand included, and clears
 * `rotated_at` so the grace period cannot bring any of them back. Called when a
 * token that was already rotated is presented again. Tokens from before
 * families existed have no family, so their own id stands in for it.
 */
export async function revokeRefreshFamily(familyId: string): Promise<number> {
  const result = await sql<{ id: string }[]>`
    UPDATE refresh_tokens
    SET revoked_at = COALESCE(revoked_at, now()), rotated_at = NULL
    WHERE family_id = ${familyId} OR id = ${familyId}
    RETURNING id;
  `;
  return result.length;
}

export async function revokeRefreshToken(jti: string): Promise<void> {
  await sql`
    UPDATE refresh_tokens SET revoked_at = now(), rotated_at = NULL WHERE jti = ${jti};
  `;
}

export async function revokeAllRefreshTokensForUser(userId: string): Promise<void> {
  await sql`
    UPDATE refresh_tokens SET revoked_at = now(), rotated_at = NULL WHERE user_id = ${userId};
  `;
}

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function verifyRefreshTokenHash(token: string, tokenHash: string): Promise<boolean> {
  return hashToken(token) === tokenHash;
}

/**
 * Stores a passkey, replacing the user's own credential with the same id.
 * Returns `null` when the id belongs to another user: credential ids are not
 * secret (login options list them), so a re-registration must never move one.
 */
export async function savePasskeyCredential(
  id: string,
  userId: string,
  publicKey: string,
  deviceName?: string
): Promise<PasskeyCredentialRecord | null> {
  const result = await sql<PasskeyCredentialRecord[]>`
    INSERT INTO passkey_credentials (id, user_id, public_key, device_name)
    VALUES (${id}, ${userId}, ${publicKey}, ${deviceName ?? null})
    ON CONFLICT (id) DO UPDATE
    SET public_key = EXCLUDED.public_key,
        device_name = EXCLUDED.device_name
    WHERE passkey_credentials.user_id = EXCLUDED.user_id
    RETURNING id, user_id, public_key, counter, device_name, created_at;
  `;
  return result[0] ?? null;
}

export async function findPasskeyCredentialWithUser(
  id: string
): Promise<(PasskeyCredentialRecord & { user: UserRecord }) | null> {
  const result = await sql<any[]>`
    SELECT
      c.id, c.user_id, c.public_key, c.counter, c.device_name, c.created_at,
      u.id AS u_id, u.username, u.password_hash, u.role, u.active, u.scopes,
      u.created_at AS u_created_at, u.updated_at AS u_updated_at
    FROM passkey_credentials c
    JOIN users u ON u.id = c.user_id
    WHERE c.id = ${id}
    LIMIT 1;
  `;
  const row = result[0];
  if (!row) return null;
  const user: UserRecord = normalizeUser({
    id: row.u_id,
    username: row.username,
    password_hash: row.password_hash,
    role: row.role,
    active: row.active,
    scopes: row.scopes,
    created_at: row.u_created_at,
    updated_at: row.u_updated_at,
  });
  return {
    id: row.id,
    user_id: row.user_id,
    public_key: row.public_key,
    counter: row.counter,
    device_name: row.device_name,
    created_at: row.created_at,
    user,
  };
}

export async function findPasskeyCredentialsByUserId(
  userId: string
): Promise<PasskeyCredentialRecord[]> {
  return await sql<PasskeyCredentialRecord[]>`
    SELECT id, user_id, public_key, counter, device_name, created_at
    FROM passkey_credentials
    WHERE user_id = ${userId}
    ORDER BY created_at DESC;
  `;
}

export async function findPasskeyCredentialsByUsername(
  username: string
): Promise<PasskeyCredentialRecord[]> {
  const result = await sql<PasskeyCredentialRecord[]>`
    SELECT c.id, c.user_id, c.public_key, c.counter, c.device_name, c.created_at
    FROM passkey_credentials c
    JOIN users u ON u.id = c.user_id
    WHERE u.username = ${username}
    ORDER BY c.created_at DESC;
  `;
  return result;
}

export async function updatePasskeyCounter(id: string, counter: number | bigint): Promise<void> {
  await sql`
    UPDATE passkey_credentials
    SET counter = ${counter}
    WHERE id = ${id};
  `;
}

export async function deletePasskeyCredential(id: string, userId: string): Promise<boolean> {
  const result = await sql<{ id: string }[]>`
    DELETE FROM passkey_credentials
    WHERE id = ${id} AND user_id = ${userId}
    RETURNING id;
  `;
  return result.length > 0;
}

export type AuthEvent = {
  event: string;
  success: boolean;
  userId?: string | null;
  username?: string | null;
  actorId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  detail?: string | null;
};

export async function insertAuthEvent(entry: AuthEvent): Promise<void> {
  await sql`
    INSERT INTO auth_events (event, success, user_id, username, actor_id, ip, user_agent, detail)
    VALUES (
      ${entry.event},
      ${entry.success},
      ${entry.userId ?? null},
      ${entry.username ?? null},
      ${entry.actorId ?? null},
      ${entry.ip ?? null},
      ${entry.userAgent ?? null},
      ${entry.detail ?? null}
    );
  `;
}

export type AuthEventRow = {
  id: string;
  event: string;
  success: boolean;
  user_id: string | null;
  username: string | null;
  actor_id: string | null;
  ip: string | null;
  user_agent: string | null;
  detail: string | null;
  created_at: string;
};

export type AuthEventFilters = {
  event?: string;
  success?: boolean;
  userId?: string;
  username?: string;
  since?: Date;
  until?: Date;
  page: number;
  pageSize: number;
};

/** Newest first. Every filter is optional; all given filters must match. */
export async function listAuthEvents(filters: AuthEventFilters): Promise<{ items: AuthEventRow[]; total: number }> {
  const event = filters.event ?? null;
  const success = filters.success ?? null;
  const userId = filters.userId ?? null;
  const username = filters.username?.toLowerCase() ?? null;
  const since = filters.since?.toISOString() ?? null;
  const until = filters.until?.toISOString() ?? null;
  const offset = (filters.page - 1) * filters.pageSize;

  const items = await sql<AuthEventRow[]>`
    SELECT id::text AS id, event, success, user_id, username, actor_id, ip, user_agent, detail, created_at
    FROM auth_events
    WHERE (${event}::text IS NULL OR event = ${event})
      AND (${success}::boolean IS NULL OR success = ${success})
      AND (${userId}::uuid IS NULL OR user_id = ${userId})
      AND (${username}::text IS NULL OR lower(username) = ${username})
      AND (${since}::timestamptz IS NULL OR created_at >= ${since})
      AND (${until}::timestamptz IS NULL OR created_at < ${until})
    ORDER BY created_at DESC, id DESC
    LIMIT ${filters.pageSize} OFFSET ${offset};
  `;

  const countResult = await sql<{ count: string }[]>`
    SELECT COUNT(*)::text AS count
    FROM auth_events
    WHERE (${event}::text IS NULL OR event = ${event})
      AND (${success}::boolean IS NULL OR success = ${success})
      AND (${userId}::uuid IS NULL OR user_id = ${userId})
      AND (${username}::text IS NULL OR lower(username) = ${username})
      AND (${since}::timestamptz IS NULL OR created_at >= ${since})
      AND (${until}::timestamptz IS NULL OR created_at < ${until});
  `;

  return { items, total: Number(countResult[0]?.count ?? 0) };
}

/** Deletes audit rows older than `retentionDays` and returns how many went. */
export async function pruneAuthEvents(retentionDays: number): Promise<number> {
  const result = await sql<{ removed: number }[]>`
    WITH pruned AS (
      DELETE FROM auth_events
      WHERE created_at < now() - make_interval(days => ${retentionDays})
      RETURNING 1
    )
    SELECT COUNT(*)::int AS removed FROM pruned;
  `;
  return result[0]?.removed ?? 0;
}
