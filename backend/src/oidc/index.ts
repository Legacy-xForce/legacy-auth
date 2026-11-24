import { config } from "../config.ts";
import { log } from "../logger.ts";
import { startOidcBackend, type OidcBackend } from "./backend.ts";
import type { AppAudience } from "../types.ts";
import { endUserAppAccess, endUserSessions } from "./sessions.ts";
import { createOidcProxyApp } from "./proxy.ts";

type State = { status: "stopped" } | { status: "running"; backend: OidcBackend } | { status: "failed"; error: unknown };

const NOT_RUNNING = "the OpenID Provider is not running";

const proxyApp = createOidcProxyApp();

let state: State = { status: "stopped" };

/**
 * The OpenID Provider as the rest of the service sees it. It is additive: when
 * it is switched off (OIDC_ENABLED=false) or fails to start, `/auth/*` and the
 * console carry on, and the OP's own paths answer 404 or 503 instead.
 */
export const oidc = {
  get running() {
    return state.status === "running";
  },

  /** The private socket the OP backend listens on, for tests that check how it is exposed. */
  get socketPath() {
    if (state.status !== "running") throw new Error(NOT_RUNNING);
    return state.backend.socketPath;
  },

  /** The provider, for tests and for ending sessions. Throws unless the OP is running. */
  get provider() {
    if (state.status !== "running") throw new Error(NOT_RUNNING);
    return state.backend.provider;
  },

  async start(): Promise<void> {
    if (state.status === "running") return;
    if (!config.oidcEnabled) return;
    try {
      state = { status: "running", backend: await startOidcBackend() };
    } catch (error) {
      // Logged loudly, but the legacy login keeps working: the OP is additive.
      log.error("[oidc] failed to start; the OpenID Provider is unavailable", undefined, error);
      state = { status: "failed", error };
    }
  },

  async stop(): Promise<void> {
    if (state.status === "running") await state.backend.stop();
    state = { status: "stopped" };
  },

  async handle(request: Request, ip: string | null): Promise<Response> {
    return await proxyApp.fetch(request, {
      socketPath: state.status === "running" ? state.backend.socketPath : "",
      ip,
      status: state.status,
    });
  },

  /** Signs a user out of every browser session at the OP. A no-op while the OP is not running. */
  async endUserSessions(userId: string): Promise<number> {
    if (state.status !== "running") return 0;
    return endUserSessions(state.backend.provider, userId);
  },

  /** Ends the sign-ins of the apps that need `audience`, after a user lost it. A no-op while the OP is not running. */
  async endUserAppAccess(userId: string, audience: AppAudience): Promise<number> {
    if (state.status !== "running") return 0;
    return endUserAppAccess(state.backend.provider, userId, audience);
  },
};
