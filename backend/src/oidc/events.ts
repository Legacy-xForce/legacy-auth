import type Provider from "oidc-provider";
import { auditOidc } from "./audit.ts";
import { enqueueBackchannelRetry } from "./backchannel.ts";
import { touchSession } from "./sessions.ts";

type OidcCtx = { oidc?: any };

/** Connects the provider's events to the audit log, the retry queue and session activity. */
export function registerProviderEvents(provider: Provider) {
  // A code was issued: the user signed in (or was already) and the app may now redeem it.
  provider.on("authorization.success", (ctx: OidcCtx) => {
    void auditOidc({ event: "oidc.code.issued", success: true, userId: ctx.oidc?.session?.accountId, detail: ctx.oidc?.client?.clientId });
  });

  provider.on("authorization.error", (ctx: OidcCtx, error: { error?: string; error_description?: string }) => {
    void auditOidc({
      event: "oidc.authorize",
      success: false,
      userId: ctx.oidc?.session?.accountId,
      detail: `${ctx.oidc?.client?.clientId ?? "unknown client"}: ${error.error}${error.error_description ? ` (${error.error_description})` : ""}`,
    });
  });

  provider.on("grant.success", (ctx: OidcCtx) => {
    void auditOidc({
      event: "oidc.token.issued",
      success: true,
      userId: ctx.oidc?.account?.accountId,
      detail: `${ctx.oidc?.client?.clientId} ${ctx.oidc?.params?.grant_type}`,
    });
  });

  // The library revokes the whole grant when a rotated refresh token is presented again.
  provider.on("grant.revoked", (ctx: OidcCtx) => {
    if (ctx.oidc?.route === "token" && ctx.oidc?.params?.grant_type === "refresh_token") {
      void auditOidc({
        event: "oidc.refresh.reuse",
        success: false,
        userId: ctx.oidc?.entities?.RefreshToken?.accountId,
        detail: `${ctx.oidc?.client?.clientId}: a rotated refresh token was presented again; the grant was revoked`,
      });
    }
  });

  provider.on("end_session.success", (ctx: OidcCtx) => {
    void auditOidc({ event: "oidc.logout", success: true, userId: ctx.oidc?.session?.accountId, detail: ctx.oidc?.client?.clientId });
  });

  // The provider tried once while ending the session; the rest is up to the retry queue.
  provider.on("backchannel.error", (_ctx: OidcCtx, error: unknown, client: { clientId: string }, accountId: string, sid: string) => {
    void enqueueBackchannelRetry(client.clientId, accountId, sid, error);
  });

  // Using a refresh token is activity: keep its browser session from idling out.
  provider.on("refresh_token.consumed", (token: { sessionUid?: string }) => {
    touchSession(token.sessionUid).catch((error) => console.error("[oidc] could not touch session", error));
  });

  provider.on("server_error", (_ctx: OidcCtx, error: Error) => {
    console.error("[oidc] server error", error);
  });
}
