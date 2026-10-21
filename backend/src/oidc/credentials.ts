import { invalidateCachedUser } from "../cache.ts";
import { findUserByUsername, updateUserPasswordHash } from "../db.ts";
import { clearUserFailures, recordFailure, retryAfterSeconds, throttleKeys } from "../throttle.ts";
import type { UserRecord } from "../types.ts";

export type PasswordLogin =
  | { ok: true; user: UserRecord }
  | { ok: false; status: 401 | 403 | 429; error: string; userId?: string; retryAfter?: number };

// Verified against when the username is unknown, so a missing account takes as long to reject as a wrong password.
let dummyHash: Promise<string> | undefined;
const getDummyHash = () => (dummyHash ??= Bun.password.hash("not-a-real-password"));

/**
 * Checks a username and password for the OP's login form, with the same
 * throttling as POST /auth/login: failures count per username and per client
 * address, and a throttled caller is refused even with the right password.
 * `ip` is the address to count against, or null when only a proxy's is known.
 */
export async function checkPasswordLogin(username: string, password: string, ip: string | null): Promise<PasswordLogin> {
  const throttle = throttleKeys(ip, username);
  const retryAfter = retryAfterSeconds(throttle);
  if (retryAfter !== null) return { ok: false, status: 429, error: "Too many failed attempts, try again later", retryAfter };

  const fail = (status: 401 | 403, error: string, userId?: string): PasswordLogin => {
    recordFailure(throttle);
    return { ok: false, status, error, userId };
  };

  const user = await findUserByUsername(username);
  if (!user) {
    await Bun.password.verify(password, await getDummyHash());
    return fail(401, "Invalid credentials");
  }
  if (!user.active) return fail(403, "Account disabled", user.id);
  if (!(await Bun.password.verify(password, user.password_hash))) return fail(401, "Invalid credentials", user.id);

  clearUserFailures(username);
  // Same upgrade /auth/login does: bcrypt hashes become Argon2 on a successful sign-in.
  if (user.password_hash.startsWith("$2")) {
    const upgraded = await updateUserPasswordHash(user.id, await Bun.password.hash(password));
    invalidateCachedUser(username);
    if (upgraded) return { ok: true, user: upgraded };
  }
  return { ok: true, user };
}
