import type { Ctx } from "./context.ts";

const asObject = (parsed: unknown): Record<string, any> | null =>
  parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, any>) : null;

/**
 * Parses a JSON object body the way the hand-rolled handlers always did: an
 * empty body is `{}`, malformed JSON and arrays/primitives are a 400 with the
 * original error strings. Hono's `c.json()` produces the response.
 */
export async function readJsonObject(c: Ctx): Promise<{ ok: true; value: Record<string, any> } | { ok: false; response: Response }> {
  let parsed: unknown;
  try { parsed = c.req.raw.body === null ? {} : await c.req.json(); }
  catch { return { ok: false, response: c.json({ error: "Malformed JSON in request body" } as any, 400) }; }
  const value = asObject(parsed);
  if (!value) return { ok: false, response: c.json({ error: "A JSON object body is required" } as any, 400) };
  return { ok: true, value };
}

/** The same object check for a plain `Request` (used by the OIDC admin router). */
export async function readJsonObjectFromRequest(request: Request): Promise<Record<string, unknown> | null> {
  try {
    return asObject(await request.json());
  } catch {
    return null;
  }
}
