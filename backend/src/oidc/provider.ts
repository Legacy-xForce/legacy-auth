import { hkdfSync } from "crypto";
import Provider, { errors, type Configuration } from "oidc-provider";
import { config } from "../config.ts";
import { findUserById } from "../db.ts";
import { UUID_PATTERN } from "../avatars.ts";
import { getKid, getPrivateKey } from "../keys.ts";
import { PostgresAdapter } from "./adapter.ts";
import { EXTRA_CLIENT_PROPERTIES, secretMatchesHash } from "./clients.ts";
import { assertPublicTarget } from "./net-safety.ts";
import { errorPage, LOGOUT_CSP, logoutPage, signedOutPage, STATIC_PAGE_CSP } from "./pages.ts";
import { RESOURCE_SERVERS, SUPPORTED_SCOPES } from "./scopes.ts";

/** `acr` of a session signed in with a password or a passkey. Higher levels are reserved for step-up. */
export const ACR_BASIC = "urn:legacy:loa:1";

/** How long a session may live from now on: the idle timeout, capped so it never outlasts the absolute one. */
export function sessionTtlSeconds(session: { loginTs?: number }, now = Math.floor(Date.now() / 1000)): number {
  // Not signed in yet: the session only has to outlive the login form.
  if (!session.loginTs) return 3600;
  const untilAbsoluteEnd = session.loginTs + config.oidcSessionAbsoluteSeconds - now;
  return Math.max(1, Math.floor(Math.min(config.oidcSessionIdleSeconds, untilAbsoluteEnd)));
}

function cookieKeys(): string[] {
  if (config.oidcCookieKeys.length > 0) return config.oidcCookieKeys;
  // One key derived from the JWT secret, so no new secret has to be provisioned.
  return [Buffer.from(hkdfSync("sha256", config.jwtSecret, "", "legacy-auth/oidc-cookies", 32)).toString("hex")];
}

/** The `__Host-` prefix requires Secure, so it is only used when the issuer is https. */
export const sessionCookieName = () => (config.jwtIssuer.startsWith("https://") ? "__Host-legacy_session" : "legacy_session");

const clientScopes = (client: { scope?: string }) => new Set((client.scope ?? "").split(" ").filter(Boolean));

export function createProvider(): Provider {
  const privateJwk = { ...getPrivateKey().export({ format: "jwk" }), use: "sig", alg: "ES256", kid: getKid() };
  const issuerOrigin = new URL(config.jwtIssuer).origin;

  const configuration: Configuration = {
    adapter: PostgresAdapter as unknown as Configuration["adapter"],
    // The signing key is the one `/.well-known/jwks.json` already publishes: it must not change.
    jwks: { keys: [privateJwk as any] },
    clientDefaults: { id_token_signed_response_alg: "ES256" },
    responseTypes: ["code"],
    clientAuthMethods: ["client_secret_basic", "none"],
    pkce: { required: () => true },
    scopes: [...SUPPORTED_SCOPES],
    // Replacing this map drops claims the library needs, so it spells out the defaults too.
    // acr/amr/auth_time are attached to the openid scope so they are always in the ID token
    // instead of only when a client asks for them.
    claims: {
      acr: null,
      sid: null,
      auth_time: null,
      iss: null,
      amr: null,
      openid: ["sub", "auth_time", "acr", "amr"],
      profile: ["preferred_username", "role"],
    },
    acrValues: [ACR_BASIC],
    routes: {
      authorization: "/authorize",
      token: "/token",
      userinfo: "/userinfo",
      end_session: "/logout",
      // The path the service already publishes its key at.
      jwks: "/.well-known/jwks.json",
    },
    cookies: {
      keys: cookieKeys(),
      names: { session: sessionCookieName() },
      long: { signed: true, httpOnly: true, sameSite: "lax", path: "/" },
      short: { signed: true, httpOnly: true, sameSite: "lax" },
    },
    ttl: {
      AccessToken: config.accessTokenTtlSeconds,
      AuthorizationCode: 60,
      IdToken: 600,
      RefreshToken: config.refreshTokenTtlSeconds,
      Grant: config.refreshTokenTtlSeconds,
      Interaction: 600,
      Session: (_ctx, session) => sessionTtlSeconds(session as { loginTs?: number }),
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    // Every refresh issues a new token; presenting an old one revokes the whole grant.
    rotateRefreshToken: true,
    // A refresh token ends with the browser session it came from, so logging out ends it too
    // (the default keeps offline_access tokens alive after logout).
    expiresWithSession: async () => true,
    extraClientMetadata: {
      properties: EXTRA_CLIENT_PROPERTIES,
      validator() {},
    },
    findAccount: async (_ctx, sub) => {
      if (!UUID_PATTERN.test(sub)) return undefined;
      const user = await findUserById(sub);
      if (!user || !user.active) return undefined;
      return {
        accountId: user.id,
        async claims(use) {
          // role and username belong to the access token and /userinfo, not the ID token.
          return { sub: user.id, ...(use === "userinfo" ? { preferred_username: user.username, role: user.role } : {}) };
        },
      };
    },
    // The legacy claims (`type`, `scopes`, `username`, `role`) stay for the resource servers that
    // still read them; the standard ones (`scope`, `client_id`, `aud`, `sid`) come from the library.
    extraTokenClaims: async (_ctx, token) => {
      const accountId = (token as { accountId?: string }).accountId;
      if (!accountId) return undefined;
      const user = await findUserById(accountId);
      if (!user || !user.active) throw new errors.InvalidGrant("the account is not available");
      // Re-checked on every issuance, refreshes included: losing an app's scope ends sessions for that app.
      const aud = (token as { aud?: string }).aud;
      const resource = Object.values(RESOURCE_SERVERS).find((entry) => entry.audience === aud);
      if (resource && !user.scopes[resource.audience]) throw new errors.InvalidGrant(`the account has no access to ${resource.audience}`);
      return { type: "access", sid: (token as { sid?: string }).sid, username: user.username, role: user.role, scopes: user.scopes };
    },
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, form) => {
          ctx.set("content-security-policy", LOGOUT_CSP);
          ctx.type = "html";
          ctx.body = logoutPage(form, { autoSubmit: Boolean(ctx.oidc?.params?.id_token_hint), origin: issuerOrigin });
        },
        postLogoutSuccessSource: async (ctx) => {
          ctx.set("content-security-policy", STATIC_PAGE_CSP);
          ctx.type = "html";
          ctx.body = signedOutPage();
        },
      },
      backchannelLogout: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: async (_ctx, _client, oneOf) => oneOf ?? undefined,
        useGrantedResource: async () => true,
        getResourceServerInfo: async (_ctx, indicator, client) => {
          const resource = RESOURCE_SERVERS[indicator];
          if (!resource) throw new errors.InvalidTarget();
          // A client only gets the scopes of this app that it is registered for.
          const allowed = clientScopes(client as { scope?: string });
          const scopes = resource.scopes.filter((scope) => allowed.has(scope));
          if (scopes.length === 0) throw new errors.InvalidTarget();
          return {
            scope: scopes.join(" "),
            audience: resource.audience,
            accessTokenTTL: config.accessTokenTtlSeconds,
            accessTokenFormat: "jwt",
            jwt: { sign: { alg: "ES256" } },
          };
        },
      },
    },
    renderError: async (ctx, out) => {
      ctx.set("content-security-policy", STATIC_PAGE_CSP);
      ctx.type = "html";
      ctx.body = errorPage(out as Record<string, unknown>);
    },
  };

  const provider = new Provider(config.jwtIssuer, configuration);
  // The service sits behind TLS-terminating proxies; the proxy layer states the scheme (see proxy.ts).
  provider.proxy = true;
  patchClientSecretComparison(provider);
  patchBackchannelLogout(provider);
  patchSessionIds(provider);
  strictAuthorizationRequests(provider);
  return provider;
}

/**
 * Two rules stricter than the library's defaults, checked before it looks at an
 * authorization request:
 *
 * - `redirect_uri` is required. With one registered, the library would
 *   otherwise fall back to it; a request must name where it is going.
 * - `nonce` is required with the `openid` scope. OIDC Core makes it optional
 *   in the code flow, but this way every ID token is bound to the request that
 *   started it.
 *
 * A refusal is an error page, never a redirect: the redirect URI has not been
 * validated yet, so it cannot be trusted as a destination.
 */
function strictAuthorizationRequests(provider: Provider) {
  provider.use(async (ctx, next) => {
    if (ctx.path === "/authorize") {
      const query = ctx.query as Record<string, string | string[] | undefined>;
      const present = (name: string) => typeof query[name] === "string" && (query[name] as string).length > 0;
      const scope = typeof query.scope === "string" ? query.scope.split(" ") : [];
      const problem = !present("redirect_uri")
        ? "redirect_uri is required"
        : scope.includes("openid") && !present("nonce")
          ? "nonce is required when the openid scope is requested"
          : null;
      if (problem) {
        const error = new errors.InvalidRequest(problem);
        ctx.status = error.statusCode;
        ctx.type = "html";
        ctx.set("content-security-policy", STATIC_PAGE_CSP);
        ctx.body = errorPage({ error: error.error, error_description: error.error_description });
        return;
      }
    }
    await next();
  });
}

/**
 * The library compares a presented client secret with the stored one in plain
 * text. Ours are stored as hashes, and a rotated-out secret keeps working until
 * its grace period ends, so the comparison is replaced. A test pins this: if a
 * library upgrade renames the method, client authentication fails closed.
 */
function patchClientSecretComparison(provider: Provider) {
  const proto = (provider as any).Client.prototype;
  proto.compareClientSecret = function compareClientSecret(this: any, presented: string) {
    if (typeof presented !== "string" || presented.length === 0) return false;
    if (secretMatchesHash(presented, this.clientSecret)) return true;
    // Extra metadata keeps its snake_case names; only the standard properties are camel-cased.
    const previousHash: string | undefined = this.legacy_previous_secret_hash;
    const previousExpiry = Number(this.legacy_previous_secret_expires_at);
    return Boolean(previousHash) && previousExpiry > Date.now() / 1000 && secretMatchesHash(presented, previousHash);
  };
}

/**
 * The library only puts a `sid` on tokens for clients that receive back-channel
 * logout. Every token derived from a browser session carries one here, so a
 * client that cannot receive logout today (the mobile app) can correlate a
 * session, and gaining a back-channel URI later changes nothing in its tokens.
 */
function patchSessionIds(provider: Provider) {
  (provider as any).Client.prototype.includeSid = () => true;
}

/** Refuses internal targets just before the library posts the logout token (see net-safety.ts). */
function patchBackchannelLogout(provider: Provider) {
  const proto = (provider as any).Client.prototype;
  const original = proto.backchannelLogout;
  proto.backchannelLogout = async function backchannelLogout(this: any, sub: string, sid: string) {
    if (!config.oidcAllowInternalBackchannel) await assertPublicTarget(this.backchannelLogoutUri);
    return original.call(this, sub, sid);
  };
}
