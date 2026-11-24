import { describe, expect, test } from "bun:test";
import { getCachedUser, cacheUser, pruneExpiredCache, toCachedUser, type CachedUser } from "../src/cache.ts";
import type { UserRecord } from "../src/types.ts";

function cachedUser(username: string): CachedUser {
  const record: UserRecord = {
    id: "00000000-0000-4000-8000-000000000001",
    username, display_name: "Cache", password_hash: "hash", role: "user", active: true,
    scopes: { calendar: true, tracker: false }, created_at: "", updated_at: "",
  };
  return toCachedUser(record);
}

describe("login cache expiry sweep", () => {
  test("keeps live entries and removes expired ones", () => {
    const suffix = Math.random().toString(36).slice(2);
    const live = `cache-live-${suffix}`;
    const stale = `cache-stale-${suffix}`;
    cacheUser(cachedUser(live));
    cacheUser(cachedUser(stale));

    // A sweep at the current instant must not disturb a fresh entry.
    pruneExpiredCache();
    expect(getCachedUser(live)).not.toBeNull();

    // A later instant stands in for wall-clock time passing past cacheTtlMs.
    const removed = pruneExpiredCache(Date.now() + 400_000);
    expect(removed).toBeGreaterThanOrEqual(1);
    expect(getCachedUser(live)).toBeNull();
    expect(getCachedUser(stale)).toBeNull();
  });
});
