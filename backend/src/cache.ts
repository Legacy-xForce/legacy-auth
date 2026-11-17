import { UserRecord } from "./types.ts";
import { config } from "./config.ts";
import { normalizeUsername } from "./usernames.ts";

export type CachedUser = Pick<UserRecord, "id" | "username" | "display_name" | "password_hash" | "role" | "active" | "scopes">;

/** The subset of a user row the login cache keeps. */
export function toCachedUser(user: UserRecord): CachedUser {
  return {
    id: user.id,
    username: user.username,
    display_name: user.display_name,
    password_hash: user.password_hash,
    role: user.role,
    active: user.active,
    scopes: user.scopes,
  };
}

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
