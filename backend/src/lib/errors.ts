import type { Ctx } from "./context.ts";

/**
 * Maps a user write failure to the HTTP response callers have always seen:
 * a unique-constraint violation means the username is taken (409), anything
 * else keeps its message and is a 500.
 */
export function userWriteErrorResponse(c: Ctx, error: unknown, fallback: string): Response {
  const message = error instanceof Error ? error.message : fallback;
  if (message.toLowerCase().includes("unique")) return c.json({ error: "Username already exists" } as any, 409);
  return c.json({ error: message } as any, 500);
}
