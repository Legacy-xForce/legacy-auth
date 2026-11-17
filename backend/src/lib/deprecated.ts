import type { Context } from "hono";
import { config } from "../config.ts";

/** The legacy login endpoints, in one place: runtime headers and OpenAPI flags both come from here. */
export const DEPRECATED_ENDPOINTS = new Set([
  "POST /auth/login",
  "POST /auth/passkey/login-options",
  "POST /auth/passkey/login-verify",
]);

export const isDeprecatedEndpoint = (method: string, path: string) =>
  DEPRECATED_ENDPOINTS.has(`${method.toUpperCase()} ${path}`);

/** Sets RFC 8594 headers on a finished Hono response for the legacy login endpoints. */
export function markDeprecated(c: Context): void {
  if (isDeprecatedEndpoint(c.req.method, c.req.path)) {
    c.res.headers.set("Deprecation", "true");
    c.res.headers.set("Link", `<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  }
}
