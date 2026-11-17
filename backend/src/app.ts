import { honoLogLayer } from "@loglayer/hono";
import { Hono, type Context, type Next } from "hono";
import { OpenAPIHono } from "@hono/zod-openapi";
import { HTTPException } from "hono/http-exception";
import { log, logLayer } from "./logger.ts";
import { applyCorsOrigin, withCorsHeaders } from "./cors.ts";
import { clientIp, resolveClientIp, type PeerLookup } from "./lib/client-ip.ts";
import type { AppEnv } from "./lib/context.ts";
import { registerRoutes } from "./routes/index.ts";
import { markDeprecated } from "./lib/deprecated.ts";
import { oidc } from "./oidc/index.ts";
import { OIDC_ROUTE_PATTERNS } from "./oidc/proxy.ts";

export type { PeerLookup };

type FrontEnv = { Bindings: PeerLookup };

/** Paths whose handlers need a JSON body even if the client sent no Content-Type. */
const JSON_BODY_PATHS = ["/auth/login", "/auth/refresh", "/auth/logout", "/auth/change-password", "/auth/me", "/admin/users"];

const normalizeJson = async (c: Context, next: Next) => {
  const contentType = c.req.header("content-type");
  if (
    c.req.raw.body !== null &&
    (!contentType || (!contentType.startsWith("application/json") && !contentType.startsWith("multipart/form-data")))
  ) {
    c.req.raw.headers.set("content-type", "application/json");
  }
  await next();
};

function createLegacyApp() {
  const app = new OpenAPIHono<AppEnv>({
    defaultHook: (result: any, c: any) => {
      if (result.success) return undefined;
      return c.json({ error: "Invalid request" }, 400);
    },
  });

  // The original handlers parsed JSON regardless of Content-Type. @hono/zod-openapi
  // rejects a missing/mismatched type with 415, so normalise it before validation.
  // Route-scoped middleware instead of a hand-built method/path set.
  for (const path of JSON_BODY_PATHS) app.use(path, normalizeJson as any);

  // Request-scoped logger on c.var.logger: a unique requestId, automatic
  // incoming/completed lines, and the resolved client IP.
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

  // The OP owns its own CORS; its paths are dispatched by the front door first.
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

const legacyApp = createLegacyApp();

function createFrontDoor() {
  const front = new Hono<FrontEnv>();

  front.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env);
    await next();
  });

  // The OP's paths are registered from the proxy's route table, before the
  // legacy app: Hono dispatches them, and they short-circuit CORS/deprecation.
  const opHandler = async (c: Context<FrontEnv>) => {
    const response = await oidc.handle(c.req.raw, clientIp(c.req.raw));
    log.info("oidc request", { method: c.req.method, path: c.req.path, status: response.status });
    return response;
  };
  for (const pattern of OIDC_ROUTE_PATTERNS) front.all(pattern, opHandler);

  // Post-processing runs only for legacy routes: Hono stops at the OP handler.
  front.use("*", async (c, next) => {
    await next();
    markDeprecated(c as any);
    applyCorsOrigin(c);
  });

  front.route("/", legacyApp as any);
  return front;
}

const frontDoor = createFrontDoor();

/** Entry point for `Bun.serve({ fetch: handleRequest })`. Bun passes the server as the 2nd argument. */
export async function handleRequest(request: Request, server: PeerLookup): Promise<Response> {
  return await frontDoor.fetch(request, server);
}
