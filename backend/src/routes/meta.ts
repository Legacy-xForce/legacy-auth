import { createRoute, type OpenAPIHono } from "@hono/zod-openapi";
import { Scalar } from "@scalar/hono-api-reference";
import { join, normalize } from "path";
import { config } from "../config.ts";
import { getJwks } from "../keys.ts";
import { assetLinks } from "../asset-links.ts";
import { JwksResponse } from "../schemas.ts";
import { applyDocOverlay } from "../docs-overlay.ts";
import { serveStaticFile } from "../static.ts";
import type { AppEnv } from "../lib/context.ts";

export function registerMetaRoutes(app: OpenAPIHono<AppEnv>) {
  app.openapi(
    createRoute({
      method: "get", path: "/.well-known/jwks.json", tags: ["Keys"],
      summary: "JSON Web Key Set",
      description: "Returns the public keys used to verify access token signatures (ES256). Consumers can use this endpoint to validate JWTs without sharing any secret.",
      responses: { 200: { description: "JWKS document", content: { "application/json": { schema: JwksResponse } } } },
    }),
    (c) => c.json(getJwks() as any, 200),
  );

  app.openapi(
    createRoute({
      method: "get", path: "/.well-known/assetlinks.json", tags: ["Keys"],
      summary: "Digital Asset Links",
      description: "Lists the Android apps (package and signing certificate SHA-256) allowed to use this host's passkeys, from PASSKEY_ANDROID_APPS.",
      responses: { 200: { description: "Asset Links statements" }, 404: { description: "No Android apps configured" } },
    }),
    (c) => {
      const statements = assetLinks();
      return statements ? c.json(statements as any, 200) : c.json({ error: "Not found" } as any, 404);
    },
  );

  // Generated once at startup, after all routes are registered, like the old
  // hand-written document.
  const openApiDocument = applyDocOverlay(app.getOpenAPIDocument({
    openapi: "3.0.3",
    info: { title: "Legacy Auth Service", version: "0.1.0", description: "Authentication service for the Legacy ecosystem." },
    servers: [{ url: "/" }],
  }) as any);

  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/openapi.json", (c) => c.json(openApiDocument));
  // Pin the Scalar bundle version so a CDN release cannot change the docs page.
  app.get("/docs", Scalar({
    url: "/openapi.json",
    pageTitle: "Legacy Auth API Docs",
    cdn: "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.80.0",
  }));

  // Frontend catch-all must be registered last. Never let an unmatched API,
  // well-known, or docs path fall through to the SPA.
  app.get("*", async (c) => {
    const pathname = new URL(c.req.url).pathname;
    if (
      pathname.startsWith("/auth/") ||
      pathname.startsWith("/admin/") ||
      pathname.startsWith("/.well-known/") ||
      pathname.startsWith("/docs/")
    ) {
      return c.json({ error: "Not found" } as any, 404);
    }
    const staticResponse = await tryServeFrontend(pathname, c.req.raw);
    return staticResponse ?? c.json({ error: "Not found" } as any, 404);
  });
}

async function tryServeFrontend(pathname: string, request: Request): Promise<Response | null> {
  let decoded: string;
  try { decoded = decodeURIComponent(pathname); }
  catch { return null; }
  const relative = normalize(decoded).replace(/^(\.\.[/\\])+/, "").replace(/^\/+/, "");
  const candidate = join(config.frontendDistDir, relative || "index.html");
  const file = Bun.file(candidate);
  if (await file.exists()) return await serveStaticFile(file, request);
  const indexFile = Bun.file(join(config.frontendDistDir, "index.html"));
  if (await indexFile.exists()) return await serveStaticFile(indexFile, request);
  return null;
}
