import "./boot-checks.run.ts";
import { serve } from "bun";
import { config } from "./config.ts";
import { initDatabase } from "./db.ts";
import { bindServer, handleRequest } from "./app.ts";
import { startAuditPruning } from "./audit-retention.ts";
import { oidc } from "./oidc/index.ts";

await initDatabase();
startAuditPruning();
await oidc.start();

const server = serve({
  port: config.port,
  fetch: handleRequest,
});
bindServer(server);

// `docker stop` sends SIGTERM. Stop taking requests, let the OP finish what it is doing (a logout
// notification in flight) and remove its socket, instead of being killed in the middle of it.
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, async () => {
    await server.stop();
    await oidc.stop();
    process.exit(0);
  });
}
