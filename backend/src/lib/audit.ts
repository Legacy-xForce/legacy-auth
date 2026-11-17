import { insertAuthEvent, type AuthEvent } from "../db.ts";
import { clientIp } from "./client-ip.ts";
import type { Ctx } from "./context.ts";

export function audit(c: Ctx, entry: Omit<AuthEvent, "ip" | "userAgent">) {
  insertAuthEvent({ ...entry, ip: clientIp(c.req.raw), userAgent: c.req.header("user-agent") ?? null }).catch((error) => {
    console.error("[audit] failed to record auth event", error);
  });
}

export function tooManyAttempts(c: Ctx, retryAfter: number) {
  return c.json({ error: "Too many failed attempts, try again later" }, 429, { "Retry-After": String(retryAfter) });
}
