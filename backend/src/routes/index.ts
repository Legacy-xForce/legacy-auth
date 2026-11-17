import type { OpenAPIHono } from "@hono/zod-openapi";
import type { AppEnv } from "../lib/context.ts";
import { registerAuthRoutes } from "./auth.ts";
import { registerProfileRoutes } from "./profile.ts";
import { registerPasskeyRoutes } from "./passkey.ts";
import { registerAdminRoutes } from "./admin.ts";
import { registerOidcAdminRoutes } from "./oidc-admin.ts";
import { registerMetaRoutes } from "./meta.ts";

/** Registers all routes. Order matters: the frontend catch-all is registered last. */
export function registerRoutes(app: OpenAPIHono<AppEnv>) {
  registerAuthRoutes(app);
  registerProfileRoutes(app);
  registerPasskeyRoutes(app);
  registerAdminRoutes(app);
  registerOidcAdminRoutes(app);
  registerMetaRoutes(app);
}
