import { OpenAPIHono } from "@hono/zod-openapi";
import { HTTPException } from "hono/http-exception";
import { config } from "./config.ts";
import { applyCorsOrigin, createCorsPreflightResponse } from "./cors.ts";
import { clientIp, resolveClientIp, type PeerLookup } from "./lib/client-ip.ts";
import type { AppEnv } from "./lib/context.ts";
import { registerRoutes } from "./routes/index.ts";
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
  const jsonBodyRoutes = new Set([
    "/auth/login", "/auth/refresh", "/auth/logout", "/auth/change-password", "/auth/me",
    "/admin/users", "/admin/oidc/clients",
  ]);
  app.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env as PeerLookup);
    const path = new URL(c.req.url).pathname.replace(/\/$/, "") || "/";
    const contentType = c.req.header("content-type");
    if (
      jsonBodyRoutes.has(path) &&
      c.req.raw.body !== null &&
      (!contentType || (!contentType.startsWith("application/json") && !contentType.startsWith("multipart/form-data")))
    ) {
      c.req.raw.headers.set("content-type", "application/json");
    }
    await next();
  });

  app.onError((error, c) => {
    if (error instanceof HTTPException) {
      return c.json({ error: error.message }, error.status as any);
    }
    console.error(error);
    return c.json({ error: "Internal server error" }, 500);
  });

  registerRoutes(app);
  return app;
}

const app = createApp();

const DEPRECATED_LOGIN_ENDPOINTS = new Set(["POST /auth/login", "POST /auth/passkey/login-options", "POST /auth/passkey/login-verify"]);

function markDeprecated(request: Request, response: Response): Response {
  if (DEPRECATED_LOGIN_ENDPOINTS.has(`${request.method} ${new URL(request.url).pathname}`)) {
    response.headers.set("Deprecation", "true");
    response.headers.set("Link", `<${config.jwtIssuer}/.well-known/openid-configuration>; rel="successor-version"`);
  }
  return response;
}

/** Entry point for `Bun.serve({ fetch: handleRequest })`. Bun passes the server as the 2nd argument. */
export async function handleRequest(request: Request, server: PeerLookup): Promise<Response> {
  resolveClientIp(request, server);
  const url = new URL(request.url);
  // The OP owns its own CORS and security headers; leave its responses untouched.
  if (oidc.handles(url.pathname)) return oidc.handle(request, clientIp(request));
  if (request.method === "OPTIONS") return applyCorsOrigin(request, createCorsPreflightResponse(request));

  // Pass the Bun server as Hono's environment so getConnInfo() can read the peer.
  const response = markDeprecated(request, await app.fetch(request, server));
  return applyCorsOrigin(request, response);
}
