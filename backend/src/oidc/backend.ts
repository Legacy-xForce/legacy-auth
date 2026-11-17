import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Provider from "oidc-provider";
import { log } from "../logger.ts";
import { startBackchannelWorker } from "./backchannel.ts";
import { ensureDefaultClients } from "./clients.ts";
import { requestContext } from "./context.ts";
import { registerProviderEvents } from "./events.ts";
import { createInteractionApp } from "./interaction.ts";
import { createProvider } from "./provider.ts";
import { startPurging } from "./sessions.ts";

export type OidcBackend = {
  provider: Provider;
  /** Unix socket the Node-style server listens on; only the proxy in this process talks to it. */
  socketPath: string;
  stop(): Promise<void>;
};

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

/** Hono only needs the method, path and headers to route; the body stays on the Node request. */
function toRequest(req: IncomingMessage, url: URL): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }
  return new Request(url.href, { method: req.method ?? "GET", headers });
}

/** The Node socket boundary: write Hono's response to the library's server response. */
async function writeResponse(res: ServerResponse, response: Response): Promise<void> {
  const headers = new Headers(response.headers);
  const cookies = headers.getSetCookie?.() ?? [];
  headers.delete("set-cookie");
  res.writeHead(response.status, Object.fromEntries(headers.entries()));
  for (const cookie of cookies) res.appendHeader("Set-Cookie", cookie);
  if (response.body) res.end(Buffer.from(await response.arrayBuffer()));
  else res.end();
}

/**
 * Runs oidc-provider, which is a Node `http` handler, next to the Bun server.
 * It listens on a private Unix socket instead of a port, so nothing outside the
 * process can reach it, and the client address it is told (`x-client-ip`) can
 * only have come from the proxy.
 */
export async function startOidcBackend(): Promise<OidcBackend> {
  const provider = createProvider();
  registerProviderEvents(provider);
  await ensureDefaultClients();

  const handleProvider = provider.callback();
  const interactionApp = createInteractionApp(provider);

  const directory = mkdtempSync(join(tmpdir(), "legacy-auth-oidc-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "oidc.sock");

  const server: Server = createServer((req, res) => {
    const context = { ip: first(req.headers["x-client-ip"]) ?? null, userAgent: first(req.headers["user-agent"]) ?? null };
    requestContext.run(context, async () => {
      try {
        const url = new URL(req.url ?? "/", "http://internal");
        if (url.pathname.startsWith("/interaction/")) {
          await writeResponse(res, await interactionApp.fetch(toRequest(req, url), { nodeReq: req, nodeRes: res, provider }));
          return;
        }
        await handleProvider(req, res);
      } catch (error) {
        log.error("[oidc] unhandled error", undefined, error);
        if (!res.headersSent) {
          res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
        }
        res.end(JSON.stringify({ error: "server_error" }));
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });

  const stopWorker = startBackchannelWorker(provider);
  const stopPurging = startPurging();

  return {
    provider,
    socketPath,
    async stop() {
      await Promise.all([stopWorker(), stopPurging()]);
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
