import { createHash } from "crypto";
import type Provider from "oidc-provider";
import { config } from "../config.ts";
import { sql } from "../db.ts";
import { log } from "../logger.ts";
import { enqueueBackchannelRetry } from "./backchannel.ts";
import { getClients, requiredResources } from "./clients.ts";
import { RESOURCE_SERVERS } from "./scopes.ts";
import type { AppAudience } from "../types.ts";

/**
 * Counts activity on a session: using one of its refresh tokens pushes the idle
 * deadline out (never past the absolute one). Without this, someone who is busy
 * in an app but never visits /authorize would be signed out after the idle
 * period, because the browser session only otherwise moves when /authorize runs.
 * The deadline lives in two places — the `expires_at` column the adapter filters
 * on and `exp` in the payload the library checks — and both are moved together.
 */
export async function touchSession(sessionUid: string | undefined): Promise<void> {
  if (!sessionUid) return;
  await sql`
    WITH target AS (
      SELECT id,
             floor(LEAST(
               extract(epoch FROM now()) + ${config.oidcSessionIdleSeconds}::double precision,
               extract(epoch FROM COALESCE(auth_time, created_at)) + ${config.oidcSessionAbsoluteSeconds}::double precision
             )) AS deadline
      FROM oidc_sessions
      WHERE id = ${sessionUid} AND revoked_at IS NULL AND expires_at > now()
    )
    UPDATE oidc_sessions s
    SET expires_at = to_timestamp(t.deadline),
        payload = jsonb_set(s.payload, '{exp}', to_jsonb(t.deadline::bigint)),
        last_seen_at = now()
    FROM target t
    WHERE s.id = t.id;
  `;
}

const hashId = (model: string, id: string) => createHash("sha256").update(`${model}:${id}`).digest("hex");

type SessionRow = { id: string; payload: { authorizations?: Record<string, { sid?: string; grantId?: string }> } };

/** Two bulk DELETEs instead of two per authorization, with identical filters. */
async function deleteGrants(grantIds: string[]): Promise<void> {
  if (grantIds.length === 0) return;
  await sql`
    DELETE FROM oidc_payloads WHERE grant_id = ANY(${sql.array(grantIds, "TEXT")}::text[]);
  `;
  await sql`
    DELETE FROM oidc_payloads
    WHERE model = 'Grant' AND id = ANY(${sql.array(grantIds.map((id) => hashId("Grant", id)), "TEXT")}::text[]);
  `;
}

/**
 * Signs a user out of every browser session: each app they were signed in to is
 * told by back-channel logout (retried if it fails), their grants and tokens
 * are deleted, and the sessions are revoked. Used when an account is disabled,
 * deleted or changes its password. Returns how many sessions it ended.
 *
 * Refresh tokens would stop working anyway (the account check fails, or the
 * session is gone); this is what makes the apps notice straight away.
 */
export async function endUserSessions(provider: Provider, userId: string): Promise<number> {
  const sessions = await sql<SessionRow[]>`
    SELECT id, payload FROM oidc_sessions
    WHERE user_id = ${userId} AND revoked_at IS NULL AND expires_at > now();
  `;

  const grantIds: string[] = [];
  for (const session of sessions) {
    for (const [clientId, authorization] of Object.entries(session.payload.authorizations ?? {})) {
      const client = (await (provider as any).Client.find(clientId)) as
        | { backchannelLogoutUri?: string; backchannelLogout(sub: string, sid: string): Promise<void> }
        | undefined;
      if (client?.backchannelLogoutUri && authorization.sid) {
        try {
          await client.backchannelLogout(userId, authorization.sid);
        } catch (error) {
          await enqueueBackchannelRetry(clientId, userId, authorization.sid, error);
        }
      }
      if (authorization.grantId) grantIds.push(authorization.grantId);
    }
  }

  await deleteGrants(grantIds);
  if (sessions.length > 0) {
    await sql`
      UPDATE oidc_sessions SET revoked_at = now()
      WHERE id = ANY(${sql.array(sessions.map((session) => session.id), "TEXT")}::text[])
        AND revoked_at IS NULL;
    `;
  }

  // Anything the sessions did not lead to (a grant whose session already expired).
  await sql`
    DELETE FROM oidc_payloads
    WHERE model IN ('Grant', 'RefreshToken', 'AccessToken', 'AuthorizationCode') AND payload->>'accountId' = ${userId};
  `;
  return sessions.length;
}

/**
 * Tells the apps that cannot work without `audience` that a user lost access to it: back-channel logout (retried
 * if it fails) and the grant is deleted, so no refresh token survives. The browser session stays, because the user
 * is still signed in to the other apps. A client for which `audience` is only an optional extra (a tracker user
 * losing the calendar) is left alone: its next refresh for that app is refused, and the rest keeps working.
 * Returns how many grants it ended.
 */
export async function endUserAppAccess(provider: Provider, userId: string, audience: AppAudience): Promise<number> {
  const indicator = Object.values(RESOURCE_SERVERS).find((resource) => resource.audience === audience)?.indicator;
  if (!indicator) return 0;

  const sessions = await sql<SessionRow[]>`
    SELECT id, payload FROM oidc_sessions
    WHERE user_id = ${userId} AND revoked_at IS NULL AND expires_at > now();
  `;
  const clientIds = [...new Set(sessions.flatMap((session) => Object.keys(session.payload.authorizations ?? {})))];
  const clients = new Map((await getClients(clientIds)).map((row) => [row.client_id, row]));

  const grantIds: string[] = [];
  for (const session of sessions) {
    for (const [clientId, authorization] of Object.entries(session.payload.authorizations ?? {})) {
      const row = clients.get(clientId);
      if (!row || !requiredResources(row).includes(indicator)) continue;
      const client = (await (provider as any).Client.find(clientId)) as
        | { backchannelLogoutUri?: string; backchannelLogout(sub: string, sid: string): Promise<void> }
        | undefined;
      if (client?.backchannelLogoutUri && authorization.sid) {
        try {
          await client.backchannelLogout(userId, authorization.sid);
        } catch (error) {
          await enqueueBackchannelRetry(clientId, userId, authorization.sid, error);
        }
      }
      if (authorization.grantId) grantIds.push(authorization.grantId);
    }
  }
  await deleteGrants(grantIds);
  return grantIds.length;
}

/** Removes expired and long-revoked rows; the library never deletes them itself. */
export async function purgeExpired(): Promise<void> {
  await sql`DELETE FROM oidc_payloads WHERE expires_at < now();`;
  await sql`DELETE FROM oidc_sessions WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days';`;
}

/** Purges now and then hourly; returns a function that stops the schedule and waits for a purge in progress. */
export function startPurging(intervalMs = 60 * 60 * 1000): () => Promise<void> {
  let inFlight: Promise<void> = Promise.resolve();
  const run = () => {
    inFlight = purgeExpired().catch((error) => log.error("[oidc] purge failed", undefined, error));
  };
  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await inFlight;
  };
}
