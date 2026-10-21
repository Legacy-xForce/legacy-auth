import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Provider from "oidc-provider";
import { startBackchannelWorker } from "./backchannel.ts";
import { ensureDefaultClients } from "./clients.ts";
import { requestContext } from "./context.ts";
import { registerProviderEvents } from "./events.ts";
import { createInteractionHandler } from "./interaction.ts";
import { createProvider } from "./provider.ts";
import { startPurging } from "./sessions.ts";

export type OidcBackend = {
  provider: Provider;
  /** Unix socket the Node-style server listens on; only the proxy in this process talks to it. */
  socketPath: string;
  stop(): Promise<void>;
};

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

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
  const handleInteraction = createInteractionHandler(provider);

  const directory = mkdtempSync(join(tmpdir(), "legacy-auth-oidc-"));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, "oidc.sock");

  const server: Server = createServer((req, res) => {
    const context = { ip: first(req.headers["x-client-ip"]) ?? null, userAgent: first(req.headers["user-agent"]) ?? null };
    requestContext.run(context, async () => {
      try {
        const url = new URL(req.url ?? "/", "http://internal");
        if (url.pathname.startsWith("/interaction/") && (await handleInteraction(req, res, url))) return;
        await handleProvider(req, res);
      } catch (error) {
        console.error("[oidc] unhandled error", error);
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
