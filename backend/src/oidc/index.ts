import { config } from "../config.ts";
import { startOidcBackend, type OidcBackend } from "./backend.ts";
import { endUserSessions } from "./sessions.ts";
import { isOidcPath, proxyToOidc } from "./proxy.ts";

type State = { status: "stopped" } | { status: "running"; backend: OidcBackend } | { status: "failed"; error: unknown };

let state: State = { status: "stopped" };

/**
 * The OpenID Provider as the rest of the service sees it. It is additive: when
 * it is switched off (OIDC_ENABLED=false) or fails to start, `/auth/*` and the
 * console carry on, and the OP's own paths answer 404 or 503 instead.
 */
export const oidc = {
  /** Whether `pathname` belongs to the OP. */
  handles: isOidcPath,

  get running() {
    return state.status === "running";
  },

  /** The private socket the OP backend listens on, for tests that check how it is exposed. */
  get socketPath() {
    if (state.status !== "running") throw new Error("the OpenID Provider is not running");
    return state.backend.socketPath;
  },

  /** The provider, for tests and for ending sessions. Throws unless the OP is running. */
  get provider() {
    if (state.status !== "running") throw new Error("the OpenID Provider is not running");
    return state.backend.provider;
  },

  async start(): Promise<void> {
    if (state.status === "running") return;
    if (!config.oidcEnabled) return;
    try {
      state = { status: "running", backend: await startOidcBackend() };
    } catch (error) {
      // Logged loudly, but the legacy login keeps working: the OP is additive.
      console.error("[oidc] failed to start; the OpenID Provider is unavailable", error);
      state = { status: "failed", error };
    }
  },

  async stop(): Promise<void> {
    if (state.status === "running") await state.backend.stop();
    state = { status: "stopped" };
  },

  handle(request: Request, ip: string | null): Promise<Response> | Response {
    if (state.status === "running") return proxyToOidc(request, state.backend.socketPath, ip);
    const failed = state.status === "failed";
    return new Response(JSON.stringify({ error: failed ? "temporarily_unavailable" : "Not found" }), {
      status: failed ? 503 : 404,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },

  /** Signs a user out of every browser session at the OP. A no-op while the OP is not running. */
  async endUserSessions(userId: string): Promise<number> {
    if (state.status !== "running") return 0;
    return endUserSessions(state.backend.provider, userId);
  },
};
