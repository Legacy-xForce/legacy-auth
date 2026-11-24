import { Hono, type Context } from "hono";
import { log } from "../logger.ts";
import { headersToRecord } from "../lib/headers.ts";
import { issuerUrl } from "./origin.ts";
import { isPrivateAddress, recordFailure, retryAfterSeconds, throttleKeys } from "../throttle.ts";

type ProxyEnv = { Bindings: { socketPath: string; ip: string | null; status: "running" | "failed" | "stopped" } };

/**
 * The paths the OP serves. One table drives Hono's route registration and
 * `isOidcPath`, so the two can't drift. Prefix entries are mounted as `path/*`.
 */
type ProxyRoute = {
  path: string;
  prefix: boolean;
  /** Hono pattern when `path/*` would be too broad (e.g. bare `/interaction` is not an OP path). */
  pattern?: string;
  throttle?: boolean;
  failure?: "status" | "redirect";
  cacheable?: boolean;
};

const ROUTES: ProxyRoute[] = [
  { path: "/authorize", prefix: false, throttle: true, failure: "redirect" },
  { path: "/authorize/", prefix: true },
  { path: "/token", prefix: false, throttle: true, failure: "status" },
  { path: "/userinfo", prefix: false },
  { path: "/logout", prefix: false },
  { path: "/logout/", prefix: true },
  { path: "/interaction/", prefix: true, pattern: "/interaction/:uid/*" },
  { path: "/.well-known/openid-configuration", prefix: false, cacheable: true },
];

export const isOidcPath = (pathname: string) =>
  ROUTES.some((route) => (route.prefix ? pathname.startsWith(route.path) : pathname === route.path));

/** The same paths as Hono route patterns, so the front door registers them instead of branching on the URL. */
export const OIDC_ROUTE_PATTERNS = ROUTES.map((route) => route.pattern ?? (route.prefix ? `${route.path}*` : route.path));

// What the client could have forged. The proxy states each of these itself.
const STRIPPED_REQUEST_HEADERS = ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-real-ip", "forwarded", "x-client-ip", "host"];

// Errors the provider sends to a client's redirect URI that say "the request was malformed or not allowed",
// as opposed to the routine answers of a silent sign-in check (login_required and the like).
const ABUSE_ERRORS = new Set(["invalid_request", "invalid_scope", "invalid_target", "invalid_client", "unauthorized_client", "unsupported_response_type", "invalid_request_uri"]);

function failedRequest(route: ProxyRoute, response: Response): boolean {
  if (route.failure === "status") return response.status >= 400 && response.status !== 429;
  if (route.failure === "redirect") {
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
function hardened(c: Context<ProxyEnv>, response: Response, cacheable: boolean): Response {
  const headers = new Headers(response.headers);
  headers.set("x-frame-options", "DENY");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  if (!headers.has("content-security-policy")) headers.set("content-security-policy", "frame-ancestors 'none'");
  if (cacheable) {
    // Public and the same for everyone, so it may be cached for a short while.
    if (!headers.has("cache-control")) headers.set("cache-control", "public, max-age=300");
  } else {
    headers.set("cache-control", "no-store");
    headers.set("pragma", "no-cache");
  }
  return c.newResponse(response.body, response.status as any, headersToRecord(headers));
}

function proxyHandler(route: ProxyRoute) {
  return async (c: Context<ProxyEnv>): Promise<Response> => {
    // The OP is additive: disabled or failed, its own paths answer 404/503 while
    // the rest of the service carries on. Same Hono app, no hand-built Response.
    if (c.env.status === "stopped") return c.json({ error: "Not found" }, 404, { "cache-control": "no-store" });
    if (c.env.status === "failed") return c.json({ error: "temporarily_unavailable" }, 503, { "cache-control": "no-store" });

    const request = c.req.raw;
    const url = new URL(request.url);
    const ip = c.env.ip;

    // Failed /token and /authorize requests are throttled per client address, like /auth/login.
    const throttle = route.throttle ? throttleKeys(ip && !isPrivateAddress(ip) ? ip : null) : [];
    const retryAfter = route.throttle ? retryAfterSeconds(throttle) : null;
    if (retryAfter !== null) {
      return hardened(
        c,
        c.json({ error: "temporarily_unavailable", error_description: "Too many failed requests, try again later" }, 429, { "retry-after": String(retryAfter) }),
        false
      );
    }

    const headers = new Headers(request.headers);
    for (const name of STRIPPED_REQUEST_HEADERS) headers.delete(name);
    // The provider derives secure cookies and absolute URLs from these; they describe the public address, not the socket.
    headers.set("host", issuerUrl.host);
    headers.set("x-forwarded-host", issuerUrl.host);
    headers.set("x-forwarded-proto", issuerUrl.protocol.replace(":", ""));
    if (ip) headers.set("x-client-ip", ip);

    let upstream: Response;
    try {
      upstream = await fetch(`http://localhost${url.pathname}${url.search}`, {
        method: request.method,
        headers,
        body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
        redirect: "manual",
        unix: c.env.socketPath,
      } as RequestInit);
    } catch (error) {
      log.error("[oidc] backend unreachable", undefined, error);
      return hardened(c, c.json({ error: "temporarily_unavailable" }, 503), false);
    }

    if (route.throttle && failedRequest(route, upstream)) recordFailure(throttle);
    return hardened(c, upstream, route.cacheable === true);
  };
}

/** The OP's own Hono router: path and method dispatch, header hardening and throttling all live here. */
export function createOidcProxyApp(): Hono<ProxyEnv> {
  const app = new Hono<ProxyEnv>();
  for (const route of ROUTES) {
    app.all(route.pattern ?? (route.prefix ? `${route.path}*` : route.path), proxyHandler(route));
  }
  return app;
}
