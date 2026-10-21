import { UUID_PATTERN } from "../avatars.ts";
import { findUserById, insertAuthEvent } from "../db.ts";
import { currentRequest } from "./context.ts";

/**
 * Records an OP event in auth_events without ever failing the request that
 * caused it. The client address and user agent come from the request being
 * served (see context.ts); the username is looked up from the user id, or taken
 * as given when there is no such user.
 */
export async function auditOidc(entry: { event: string; success: boolean; userId?: string | null; username?: string | null; detail?: string | null }) {
  const { ip, userAgent } = currentRequest();
  try {
    const user = entry.userId && UUID_PATTERN.test(entry.userId) ? await findUserById(entry.userId) : null;
    await insertAuthEvent({
      event: entry.event,
      success: entry.success,
      userId: user?.id ?? null,
      // A name that was typed but belongs to nobody (or whose attempt was throttled before a lookup) is
      // still recorded, so guessing at accounts leaves a trail that can be searched by name.
      username: user?.username ?? entry.username ?? null,
      detail: entry.detail ?? null,
      ip,
      userAgent,
    });
  } catch (error) {
    console.error("[audit] failed to record OIDC event", error);
  }
}
