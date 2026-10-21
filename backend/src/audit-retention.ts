import { config } from "./config.ts";
import { pruneAuthEvents } from "./db.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Deletes audit rows older than the retention period; 0 days keeps everything. */
export async function pruneAuditNow(retentionDays = config.auditRetentionDays): Promise<number> {
  if (retentionDays <= 0) return 0;
  const removed = await pruneAuthEvents(retentionDays);
  if (removed > 0) {
    console.log(`[audit] pruned ${removed} auth_events older than ${retentionDays} days`);
  }
  return removed;
}

/** Prunes now and then once a day; returns a function that stops the schedule. */
export function startAuditPruning(intervalMs = DAY_MS): () => void {
  const run = () => {
    pruneAuditNow().catch((error) => console.error("[audit] pruning failed", error));
  };
  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
