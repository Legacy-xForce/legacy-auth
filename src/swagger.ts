import { join } from "node:path";

const swaggerAssetDir = join(process.cwd(), "node_modules", "swagger-ui-dist");

const swaggerAssetContentTypes: Record<string, string> = {
  "swagger-ui.css": "text/css;charset=utf-8",
  "swagger-ui-bundle.js": "application/javascript;charset=utf-8",
  "swagger-ui-standalone-preset.js": "application/javascript;charset=utf-8",
  "favicon-16x16.png": "image/png",
  "favicon-32x32.png": "image/png",
  "oauth2-redirect.html": "text/html;charset=utf-8",
};

export const htmlHeaders = {
  "Content-Type": "text/html;charset=utf-8",
};

export const jsonHeaders = {
  "Content-Type": "application/json;charset=utf-8",
};

export function createSwaggerUiResponse() {
  return new Response(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Legacy Auth API Docs</title>
    <link rel="stylesheet" href="/docs/swagger-ui.css" />
    <style>
      body {
        margin: 0;
        background: #0f172a;
      }
      .swagger-ui .topbar {
        display: none;
      }
      .swagger-ui .scheme-container {
        background: #111827;
        box-shadow: none;
      }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="/docs/swagger-ui-bundle.js" defer></script>
    <script src="/docs/swagger-ui-standalone-preset.js" defer></script>
    <script>
      window.addEventListener("load", () => {
        window.ui = SwaggerUIBundle({
          url: "/openapi.json",
          dom_id: "#swagger-ui",
          deepLinking: true,
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
          layout: "BaseLayout"
        });
      });
    </script>
  </body>
</html>`, {
    status: 200,
    headers: htmlHeaders,
  });
}

export function createSwaggerAssetResponse(assetName: string) {
  const contentType = swaggerAssetContentTypes[assetName];
  if (!contentType) {
    return null;
  }

  return new Response(Bun.file(join(swaggerAssetDir, assetName)), {
    status: 200,
    headers: {
      "Content-Type": contentType,
    },
  });
}
