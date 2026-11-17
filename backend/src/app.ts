import { honoLogLayer } from "@loglayer/hono";
import { OpenAPIHono } from "@hono/zod-openapi";
import { HTTPException } from "hono/http-exception";
import { log, logLayer } from "./logger.ts";
import { applyCorsOrigin, withCorsHeaders } from "./cors.ts";
import { clientIp, resolveClientIp, type PeerLookup } from "./lib/client-ip.ts";
import type { AppEnv } from "./lib/context.ts";
import { registerRoutes } from "./routes/index.ts";
import { markDeprecated } from "./lib/deprecated.ts";
import { oidc } from "./oidc/index.ts";

export type { PeerLookup };

function createApp() {
  const app = new OpenAPIHono<AppEnv>({
    defaultHook: (result: any, c: any) => {
      if (result.success) return undefined;
      return c.json({ error: "Invalid request" }, 400);
    },
  });

  // The original handlers parsed JSON regardless of Content-Type. @hono/zod-openapi
  // rejects a missing/mismatched type with 415, so normalise it for JSON routes
  // before the validators run. Multipart/urlencoded routes keep their own type.
  // Only routes whose handler takes a Zod-validated JSON body need this. The
  // OIDC admin router parses JSON itself, and GET paths have no body at all.
  const jsonBodyRoutes = new Set([
    "POST /auth/login", "POST /auth/refresh", "POST /auth/logout", "POST /auth/change-password",
    "PATCH /auth/me", "POST /admin/users",
  ]);
  app.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env as PeerLookup);
    const path = new URL(c.req.url).pathname.replace(/\/$/, "") || "/";
    const route = `${c.req.method.toUpperCase()} ${path}`;
    const contentType = c.req.header("content-type");
    if (
      jsonBodyRoutes.has(route) &&
      c.req.raw.body !== null &&
      (!contentType || (!contentType.startsWith("application/json") && !contentType.startsWith("multipart/form-data")))
    ) {
      c.req.raw.headers.set("content-type", "application/json");
    }
    await next();
  });

  // Request-scoped logger on c.var.logger: a unique requestId, automatic
  // incoming/completed lines, and per-request context (the resolved client IP).
  // The OIDC proxy bypasses Hono and is logged separately in handleRequest.
  app.use(honoLogLayer({
    instance: logLayer,
    contextFn: ({ request }) => ({ ip: clientIp(request) }),
  }));

  app.onError((error, c) => {
    if (error instanceof HTTPException) {
      return c.json({ error: error.message }, error.status as any);
    }
    const requestLogger = c.var.logger ?? logLayer;
    requestLogger.withError(error).error("unhandled request error");
    return c.json({ error: "Internal server error" }, 500);
  });

  // Preflight for the legacy API/console lives in Hono like every other route.
  // The OP owns its own CORS, and its paths are dispatched before app.fetch.
  app.options("*", (c) => {
    const requestedHeaders = c.req.header("access-control-request-headers");
    const headers = withCorsHeaders({ "Access-Control-Max-Age": "86400" });
    // Echoed rather than "*": a wildcard does not cover Authorization.
    if (requestedHeaders) headers.set("Access-Control-Allow-Headers", requestedHeaders);
    return c.body(null, 204, Object.fromEntries(headers.entries()));
  });

  registerRoutes(app);
  return app;
}

const app = createApp();

/** Entry point for `Bun.serve({ fetch: handleRequest })`. Bun passes the server as the 2nd argument. */
export async function handleRequest(request: Request, server: PeerLookup): Promise<Response> {
  resolveClientIp(request, server);
  const url = new URL(request.url);
  // The OP owns its own CORS and security headers; leave its responses untouched.
  if (oidc.handles(url.pathname)) {
    const response = await oidc.handle(request, clientIp(request));
    log.info("oidc request", { method: request.method, path: url.pathname, status: response.status });
    return response;
  }
  // Pass the Bun server as Hono's environment so getConnInfo() can read the peer.
  const response = markDeprecated(request, await app.fetch(request, server));
  return applyCorsOrigin(request, response);
}
