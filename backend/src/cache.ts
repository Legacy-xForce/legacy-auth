import { UserRecord } from "./types.ts";
import { config } from "./config.ts";
import { normalizeUsername } from "./usernames.ts";

type CachedUser = Pick<UserRecord, "id" | "username" | "display_name" | "password_hash" | "role" | "active" | "scopes">;

type CacheEntry = {
  user: CachedUser;
  expiresAt: number;
};

const cache = new Map<string, CacheEntry>();

export function getCachedUser(username: string) {
  const key = normalizeUsername(username);
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.user;
}

export function cacheUser(user: CachedUser) {
  cache.set(normalizeUsername(user.username), {
    user,
    expiresAt: Date.now() + config.cacheTtlMs,
  });
}

export function invalidateCachedUser(username: string) {
  cache.delete(normalizeUsername(username));
}

export function clearCache() {
  cache.clear();
}
