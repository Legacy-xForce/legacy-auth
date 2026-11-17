import { OpenAPIHono } from "@hono/zod-openapi";
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

  app.use("*", async (c, next) => {
    resolveClientIp(c.req.raw, c.env as PeerLookup);
    await next();
  });

  app.onError((error, c) => {
    console.error(error);
    return c.json({ error: error instanceof Error ? error.message : "Internal server error" }, 500);
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
