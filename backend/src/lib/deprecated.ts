import { config } from "../config.ts";

/** The legacy login endpoints, in one place: runtime headers and OpenAPI flags both come from here. */
export const DEPRECATED_ENDPOINTS = new Set([
  "POST /auth/login",
  "POST /auth/passkey/login-options",
  "POST /auth/passkey/login-verify",
]);

export const isDeprecatedEndpoint = (method: string, path: string) =>
  DEPRECATED_ENDPOINTS.has(`${method.toUpperCase()} ${path}`);

/** Adds the RFC 8594 deprecation headers the legacy login endpoints still carry. */
export function markDeprecated(request: Request, response: Response): Response {
  const path = new URL(request.url).pathname;
  if (isDeprecatedEndpoint(request.method, path)) {
    response.headers.set("Deprecation", "true");
    response.headers.set("Link", `<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  }
  return response;
}
