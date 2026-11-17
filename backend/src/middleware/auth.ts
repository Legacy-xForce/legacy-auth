import { verifyAccessToken } from "../jwt.ts";
import { findUserById } from "../db.ts";
import type { UserRecord } from "../types.ts";
import type { Ctx } from "../lib/context.ts";

type AuthResult = { ok: true; user: UserRecord } | { ok: false; response: Response };

function bearerToken(c: Ctx): string {
  const header = c.req.header("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
}

async function resolveUser(c: Ctx): Promise<AuthResult> {
  const token = bearerToken(c);
  if (!token) return { ok: false, response: c.json({ error: "Authorization bearer token is required" }, 401) };
  let payload;
  try { payload = verifyAccessToken(token); }
  catch { return { ok: false, response: c.json({ error: "Invalid access token" }, 401) }; }
  const user = await findUserById(payload.sub);
  if (!user) return { ok: false, response: c.json({ error: "Invalid access token" }, 401) };
  if (!user.active) return { ok: false, response: c.json({ error: "Account disabled" }, 403) };
  return { ok: true, user };
}

/** Verifies the bearer token, attaches the user to the context, then continues. */
export const requireAuth = async (c: Ctx, next: () => Promise<void>) => {
  const result = await resolveUser(c);
  if (!result.ok) return result.response;
  c.set("user", result.user);
  await next();
};

/** requireAuth plus an admin-role check. */
export const requireAdmin = async (c: Ctx, next: () => Promise<void>) => {
  const result = await resolveUser(c);
  if (!result.ok) return result.response;
  if (result.user.role !== "admin") return c.json({ error: "Admin role required" }, 403);
  c.set("user", result.user);
  await next();
};
