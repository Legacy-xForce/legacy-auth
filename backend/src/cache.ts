import { UserRecord } from "./types.ts";
import { config } from "./config.ts";

type CacheEntry = {
  user: Pick<UserRecord, "id" | "username" | "password_hash" | "role" | "active" | "locked" | "scopes">;
  expiresAt: number;
};

const cache = new Map<string, CacheEntry>();

export function getCachedUser(username: string) {
  const entry = cache.get(username);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(username);
    return null;
  }
  return entry.user;
}

export function cacheUser(user: Pick<UserRecord, "id" | "username" | "password_hash" | "role" | "active" | "locked" | "scopes">) {
  cache.set(user.username, {
    user,
    expiresAt: Date.now() + config.cacheTtlMs,
  });
}

export function invalidateCachedUser(username: string) {
  cache.delete(username);
}

export function clearCache() {
  cache.clear();
}
