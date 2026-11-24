/**
 * Hono's response helpers take a plain header record. Collect repeated values
 * as arrays so none are lost the way `Object.fromEntries(Headers)` would lose
 * all but the last value of Set-Cookie, WWW-Authenticate, Link, etc.
 */
export function headersToRecord(headers: Headers): Record<string, string | string[]> {
  const record: Record<string, string | string[]> = {};
  for (const [key, value] of headers.entries()) {
    const existing = record[key];
    if (key === "set-cookie") {
      record[key] = headers.getSetCookie?.() ?? [value];
    } else if (existing === undefined) {
      record[key] = value;
    } else {
      record[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
    }
  }
  return record;
}
