import { config } from "./config.ts";

const corsBaseHeaders = {
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*",
};

const allowedOrigins = new Set(config.corsAllowedOrigins);

if (allowedOrigins.size === 0) {
  console.warn("[cors] CORS_ALLOWED_ORIGINS not set — any web origin may call this API");
}

export function withCorsHeaders(init: HeadersInit = {}) {
  const headers = new Headers(init);
  for (const [key, value] of Object.entries(corsBaseHeaders)) {
    headers.set(key, value);
  }
  return headers;
}

/**
 * Sets `Access-Control-Allow-Origin` on a finished response. With an allowlist
 * the request's origin is echoed only when listed; other origins get no header,
 * so the browser refuses to hand them the response.
 */
export function applyCorsOrigin(request: Request, response: Response): Response {
  if (allowedOrigins.size === 0) {
    response.headers.set("Access-Control-Allow-Origin", "*");
    return response;
  }
  response.headers.append("Vary", "Origin");
  const origin = request.headers.get("origin");
  if (origin && allowedOrigins.has(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin);
  }
  return response;
}

export function createCorsPreflightResponse(request: Request) {
  const requestedHeaders = request.headers.get("access-control-request-headers");
  const headers = withCorsHeaders({ "Access-Control-Max-Age": "86400" });
  // Echoed rather than "*": a wildcard does not cover Authorization.
  if (requestedHeaders) headers.set("Access-Control-Allow-Headers", requestedHeaders);

  return new Response(null, { status: 204, headers });
}
