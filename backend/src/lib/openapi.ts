import type { OpenAPIHono } from "@hono/zod-openapi";
import type { Handler, MiddlewareHandler } from "hono";
import type { AppEnv } from "./context.ts";

type DocumentedRoute = {
  method: string;
  path: string;
  getRoutingPath(): string;
};

/**
 * Registers OpenAPI metadata for a route whose runtime validation intentionally
 * stays in its handler (exact error strings, multipart bodies, opaque payloads).
 * The route is registered on Hono without Zod validators.
 */
export function documentOnly(
  app: OpenAPIHono<AppEnv, any, any>,
  route: DocumentedRoute,
  ...handlers: Array<MiddlewareHandler<any, any, any> | Handler<any, any, any>>
) {
  app.openAPIRegistry.registerPath(route as any);
  app.on([route.method as any], [route.getRoutingPath()], ...(handlers as any[]));
}

/** Registers docs for an operation handled by a shared catch-all route. */
export function documentSchema(app: OpenAPIHono<AppEnv, any, any>, route: DocumentedRoute) {
  app.openAPIRegistry.registerPath(route as any);
}
