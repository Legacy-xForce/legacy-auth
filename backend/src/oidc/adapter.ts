import { createHash } from "crypto";
import { errors } from "oidc-provider";
import { sql } from "../db.ts";
import { findClientMetadata } from "./clients.ts";
import { currentRequest } from "./context.ts";

/**
 * Storage for oidc-provider on Postgres.
 *
 * Bearer values never reach the database. The library hands us the token or
 * cookie value as `id` (and repeats it as `payload.jti`), so rows are keyed by
 * a hash of it and `jti` is stripped from what is stored and put back when a
 * row is read. A leaked table therefore cannot be replayed.
 */

type Payload = Record<string, any>;

const hashId = (model: string, id: string) => createHash("sha256").update(`${model}:${id}`).digest("hex");

const withoutJti = (payload: Payload): Payload => {
  const { jti: _jti, ...rest } = payload;
  return rest;
};

const epochSeconds = (value: Date | string) => Math.floor(new Date(value).getTime() / 1000);

type PayloadRow = { payload: Payload; consumed_at: Date | string | null };

function restore(row: PayloadRow, id: string): Payload {
  return {
    ...row.payload,
    jti: id,
    ...(row.consumed_at ? { consumed: epochSeconds(row.consumed_at) } : {}),
  };
}

type SessionRow = { payload: Payload };

export class PostgresAdapter {
  constructor(private readonly model: string) {}

  async upsert(id: string, payload: Payload, expiresIn: number): Promise<void> {
    if (this.model === "Session") return this.upsertSession(id, payload, expiresIn);
    if (this.model === "Client") throw new Error("clients are managed through the admin API");

    await sql`
      INSERT INTO oidc_payloads (model, id, payload, grant_id, user_code, uid, expires_at)
      VALUES (
        ${this.model},
        ${hashId(this.model, id)},
        ${withoutJti(payload)}::jsonb,
        ${payload.grantId ?? null},
        ${payload.userCode ?? null},
        ${payload.uid ?? null},
        now() + make_interval(secs => ${expiresIn}::double precision)
      )
      ON CONFLICT (model, id) DO UPDATE SET
        payload = EXCLUDED.payload,
        grant_id = EXCLUDED.grant_id,
        user_code = EXCLUDED.user_code,
        uid = EXCLUDED.uid,
        expires_at = EXCLUDED.expires_at;
    `;
  }

  async find(id: string): Promise<Payload | undefined> {
    if (this.model === "Client") return findClientMetadata(id);
    if (this.model === "Session") return this.findSession("token_hash", hashId("Session", id), id);

    const rows = await sql<PayloadRow[]>`
      SELECT payload, consumed_at FROM oidc_payloads
      WHERE model = ${this.model} AND id = ${hashId(this.model, id)} AND expires_at > now();
    `;
    return rows[0] ? restore(rows[0], id) : undefined;
  }

  async findByUid(uid: string): Promise<Payload | undefined> {
    if (this.model === "Session") return this.findSession("id", uid);

    const rows = await sql<PayloadRow[]>`
      SELECT payload, consumed_at FROM oidc_payloads
      WHERE model = ${this.model} AND uid = ${uid} AND expires_at > now()
      LIMIT 1;
    `;
    // `findByUid` is only used for models whose bearer value is not needed back
    // (interactions are addressed by their uid); the library tolerates a missing jti.
    return rows[0] ? { ...rows[0].payload, ...(rows[0].consumed_at ? { consumed: epochSeconds(rows[0].consumed_at) } : {}) } : undefined;
  }

  // Device-code flow is not enabled.
  async findByUserCode(_userCode: string): Promise<Payload | undefined> {
    return undefined;
  }

  /**
   * Marks a code or refresh token as used. Throws if it already was: the
   * library reads, then consumes, so two concurrent requests with the same
   * code could otherwise both succeed. The loser gets `invalid_grant`.
   */
  async consume(id: string): Promise<void> {
    const rows = await sql`
      UPDATE oidc_payloads SET consumed_at = now()
      WHERE model = ${this.model} AND id = ${hashId(this.model, id)} AND consumed_at IS NULL
      RETURNING 1 AS ok;
    `;
    if (rows.length === 0) throw new errors.InvalidGrant("grant request is invalid");
  }

  async destroy(id: string): Promise<void> {
    if (this.model === "Session") {
      await sql`UPDATE oidc_sessions SET revoked_at = now() WHERE token_hash = ${hashId("Session", id)} AND revoked_at IS NULL;`;
      return;
    }
    await sql`DELETE FROM oidc_payloads WHERE model = ${this.model} AND id = ${hashId(this.model, id)};`;
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await sql`DELETE FROM oidc_payloads WHERE model = ${this.model} AND grant_id = ${grantId};`;
  }

  // ---- sessions ---------------------------------------------------------

  private async upsertSession(id: string, payload: Payload, expiresIn: number): Promise<void> {
    const { ip, userAgent } = currentRequest();
    const uid = payload.uid as string;
    const amr = Array.isArray(payload.amr) ? sql.array(payload.amr, "TEXT") : null;
    const authTime = typeof payload.loginTs === "number" ? new Date(payload.loginTs * 1000).toISOString() : null;

    // The stable uid is the row key. Rotating the cookie value (done at login)
    // replaces token_hash; a row that was revoked is only revived by such a
    // rotation, never by a stale save of the revoked cookie value.
    await sql`
      INSERT INTO oidc_sessions (id, token_hash, user_id, auth_time, amr, payload, expires_at, ip, user_agent)
      VALUES (
        ${uid},
        ${hashId("Session", id)},
        ${payload.accountId ?? null},
        ${authTime},
        ${amr},
        ${withoutJti(payload)}::jsonb,
        now() + make_interval(secs => ${expiresIn}::double precision),
        ${ip},
        ${userAgent}
      )
      ON CONFLICT (id) DO UPDATE SET
        token_hash = EXCLUDED.token_hash,
        user_id = EXCLUDED.user_id,
        auth_time = EXCLUDED.auth_time,
        amr = EXCLUDED.amr,
        payload = EXCLUDED.payload,
        expires_at = EXCLUDED.expires_at,
        ip = COALESCE(EXCLUDED.ip, oidc_sessions.ip),
        user_agent = COALESCE(EXCLUDED.user_agent, oidc_sessions.user_agent),
        last_seen_at = now(),
        revoked_at = NULL
      WHERE oidc_sessions.revoked_at IS NULL OR oidc_sessions.token_hash <> EXCLUDED.token_hash;
    `;
  }

  private async findSession(column: "token_hash" | "id", value: string, cookieId?: string): Promise<Payload | undefined> {
    const rows = await sql<SessionRow[]>`
      SELECT payload FROM oidc_sessions
      WHERE ${sql.unsafe(column)} = ${value} AND revoked_at IS NULL AND expires_at > now()
      LIMIT 1;
    `;
    if (!rows[0]) return undefined;
    return { ...rows[0].payload, ...(cookieId ? { jti: cookieId } : {}) };
  }
}
