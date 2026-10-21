import type Provider from "oidc-provider";
import { config } from "../config.ts";
import { sql } from "../db.ts";
import { auditOidc } from "./audit.ts";

type RetryRow = { id: string; client_id: string; account_id: string; sid: string; attempts: number };

const MAX_DETAIL = 300;
const brief = (error: unknown) => String((error as Error)?.message ?? error).slice(0, MAX_DETAIL);

/**
 * Remembers a back-channel logout that failed, so it is retried with backoff
 * instead of leaving the app signed in. `attempts` is how many tries have been made.
 */
export async function enqueueBackchannelRetry(clientId: string, accountId: string, sid: string, error: unknown, attempts = 1) {
  const delay = config.oidcBackchannelRetryDelaysMs[attempts - 1];
  if (delay === undefined) {
    await auditOidc({ event: "oidc.backchannel", success: false, userId: accountId, detail: `${clientId}: gave up after ${attempts} attempts: ${brief(error)}` });
    return;
  }
  await sql`
    INSERT INTO oidc_backchannel_retries (client_id, account_id, sid, attempts, next_attempt_at, last_error)
    VALUES (${clientId}, ${accountId}, ${sid}, ${attempts}, now() + make_interval(secs => ${delay / 1000}::double precision), ${brief(error)});
  `;
  await auditOidc({ event: "oidc.backchannel", success: false, userId: accountId, detail: `${clientId}: attempt ${attempts} failed, retrying in ${delay}ms: ${brief(error)}` });
}

/**
 * Delivers every retry that is due. A row is claimed by pushing its due time
 * forward, so several replicas never send the same one twice, and a crash
 * mid-delivery just means it is tried again later. Returns how many it handled.
 */
export async function processDueRetries(provider: Provider): Promise<number> {
  const claimed = await sql<RetryRow[]>`
    WITH due AS (
      SELECT id FROM oidc_backchannel_retries
      WHERE next_attempt_at <= now()
      ORDER BY next_attempt_at
      LIMIT 20
      FOR UPDATE SKIP LOCKED
    )
    UPDATE oidc_backchannel_retries r
    SET next_attempt_at = now() + interval '2 minutes'
    FROM due WHERE r.id = due.id
    RETURNING r.id::text AS id, r.client_id, r.account_id, r.sid, r.attempts;
  `;

  for (const row of claimed) {
    const client = (await (provider as any).Client.find(row.client_id)) as { backchannelLogoutUri?: string; backchannelLogout(sub: string, sid: string): Promise<void> } | undefined;
    if (!client?.backchannelLogoutUri) {
      await sql`DELETE FROM oidc_backchannel_retries WHERE id = ${row.id}::bigint;`;
      await auditOidc({ event: "oidc.backchannel", success: false, userId: row.account_id, detail: `${row.client_id}: dropped, the client no longer receives back-channel logout` });
      continue;
    }
    try {
      await client.backchannelLogout(row.account_id, row.sid);
      await sql`DELETE FROM oidc_backchannel_retries WHERE id = ${row.id}::bigint;`;
      await auditOidc({ event: "oidc.backchannel", success: true, userId: row.account_id, detail: `${row.client_id}: delivered on attempt ${row.attempts + 1}` });
    } catch (error) {
      await sql`DELETE FROM oidc_backchannel_retries WHERE id = ${row.id}::bigint;`;
      await enqueueBackchannelRetry(row.client_id, row.account_id, row.sid, error, row.attempts + 1);
    }
  }
  return claimed.length;
}

/** Polls for due retries; returns a function that stops it and waits for a delivery in progress. */
export function startBackchannelWorker(provider: Provider): () => Promise<void> {
  let current: Promise<void> | null = null;
  const tick = () => {
    if (current) return;
    current = processDueRetries(provider)
      .then(() => undefined)
      .catch((error) => console.error("[oidc] back-channel retry worker failed", error))
      .finally(() => {
        current = null;
      });
  };
  const timer = setInterval(tick, config.oidcBackchannelPollMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await current;
  };
}
