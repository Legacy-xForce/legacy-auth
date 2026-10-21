import { config } from "../config.ts";
import { isPrivateAddress, recordFailure, retryAfterSeconds, throttleKeys } from "../throttle.ts";

/** Paths the OP serves. Everything else on this service is the legacy API or the console. */
const EXACT = new Set(["/authorize", "/token", "/userinfo", "/logout", "/.well-known/openid-configuration"]);
const PREFIXES = ["/authorize/", "/logout/", "/interaction/"];

export const isOidcPath = (pathname: string) => EXACT.has(pathname) || PREFIXES.some((prefix) => pathname.startsWith(prefix));

// What the client could have forged. The proxy states each of these itself.
const STRIPPED_REQUEST_HEADERS = ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "forwarded", "x-client-ip", "host"];

// Errors the provider sends to a client's redirect URI that say "the request was malformed or not allowed",
// as opposed to the routine answers of a silent sign-in check (login_required and the like).
const ABUSE_ERRORS = new Set(["invalid_request", "invalid_scope", "invalid_target", "invalid_client", "unauthorized_client", "unsupported_response_type", "invalid_request_uri"]);

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

function failureOf(pathname: string, response: Response): boolean {
  if (pathname === "/token") return response.status >= 400 && response.status !== 429;
  if (pathname === "/authorize") {
    if (response.status === 400 || response.status === 401 || response.status === 403) return true;
    const location = response.headers.get("location");
    if (!location) return false;
    try {
      const error = new URL(location, "http://x").searchParams.get("error");
      return error !== null && ABUSE_ERRORS.has(error);
    } catch {
      return false;
    }
  }
  return false;
}

/** Headers every OP response carries: no framing, no Referer leak, nothing cached (except the public discovery document, briefly). */
function hardened(response: Response, pathname: string): Response {
  const headers = new Headers(response.headers);
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  if (!headers.has("content-security-policy")) headers.set("content-security-policy", "frame-ancestors 'none'");
  if (pathname === "/.well-known/openid-configuration") {
    // Public and the same for everyone, so it may be cached for a short while.
    if (!headers.has("cache-control")) headers.set("cache-control", "public, max-age=300");
  } else {
    headers.set("cache-control", "no-store");
    headers.set("pragma", "no-cache");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Hands a request to the OP backend over its Unix socket and returns its answer.
 * `ip` is the client address as the caller worked it out (see clientIp in app.ts).
 */
export async function proxyToOidc(request: Request, socketPath: string, ip: string | null): Promise<Response> {
  const url = new URL(request.url);
  const issuer = new URL(config.jwtIssuer);

  // Failed /token and /authorize requests are throttled per client address, like /auth/login.
  const throttled = url.pathname === "/token" || url.pathname === "/authorize";
  const throttle = throttled ? throttleKeys(ip && !isPrivateAddress(ip) ? ip : null) : [];
  const retryAfter = throttled ? retryAfterSeconds(throttle) : null;
  if (retryAfter !== null) {
    return hardened(
      json(429, { error: "temporarily_unavailable", error_description: "Too many failed requests, try again later" }, { "retry-after": String(retryAfter) }),
      url.pathname
    );
  }

  const headers = new Headers(request.headers);
  for (const name of STRIPPED_REQUEST_HEADERS) headers.delete(name);
  // The provider derives secure cookies and absolute URLs from these; they describe the public address, not the socket.
  headers.set("host", issuer.host);
  headers.set("x-forwarded-host", issuer.host);
  headers.set("x-forwarded-proto", issuer.protocol.replace(":", ""));
  if (ip) headers.set("x-client-ip", ip);

  let upstream: Response;
  try {
    upstream = await fetch(`http://localhost${url.pathname}${url.search}`, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
      unix: socketPath,
    } as RequestInit);
  } catch (error) {
    console.error("[oidc] backend unreachable", error);
    return hardened(json(503, { error: "temporarily_unavailable" }), url.pathname);
  }

  if (throttled && failureOf(url.pathname, upstream)) recordFailure(throttle);
  return hardened(upstream, url.pathname);
}
