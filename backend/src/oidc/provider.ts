import { hkdfSync } from "crypto";
import Provider, { errors, type Configuration } from "oidc-provider";
import { config } from "../config.ts";
import { findUserById } from "../db.ts";
import { UUID_PATTERN } from "../avatars.ts";
import { getKid, getPrivateKey } from "../keys.ts";
import { PostgresAdapter } from "./adapter.ts";
import { EXTRA_CLIENT_PROPERTIES, redirectOriginAllowed, redirectUriAllowed, secretMatchesHash } from "./clients.ts";
import { assertPublicTarget } from "./net-safety.ts";
import { errorPage, LOGOUT_CSP, logoutPage, signedOutPage, STATIC_PAGE_CSP } from "./pages.ts";
import { entitledResourceScopes, RESOURCE_SERVERS, resourcesForScopes, SUPPORTED_SCOPES } from "./scopes.ts";

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

/** The registry settings the provider keeps on a client (see clients.ts `EXTRA_CLIENT_PROPERTIES`). */
type LegacyClient = { legacy_primary_resource?: string; legacy_default_resources?: string[]; applicationType?: string };

/** Native apps (a custom-scheme redirect, see clients.ts) are not tied to the browser session. */
const isNative = (client?: LegacyClient) => client?.applicationType === "native";

const asList = (value: unknown): string[] => (Array.isArray(value) ? value.map(String) : typeof value === "string" ? [value] : []);

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
    // A public browser client calls the token, userinfo and revocation endpoints from the origin its
    // app runs at. The library's default only accepts an origin that is exactly a registered redirect
    // URI's origin; a Cloudflare Pages preview runs at a subdomain of one (legacy-auth#14), so that
    // origin is accepted too. A confidential client is still limited to /userinfo, as by default.
    clientBasedCORS: (ctx, origin, client) => {
      if (ctx.oidc.route !== "userinfo" && client.clientAuthMethod !== "none") return false;
      return redirectOriginAllowed(origin, client.redirectUris);
    },
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
      profile: ["preferred_username", "name", "role"],
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
      // Rotation gives every refresh token a fresh lifetime, so for a native app this is "unused for"; the grant
      // (set once, when it is created at consent) is what bounds the whole sign-in. A web client's grant
      // ends with its first refresh token, which in turn ends with its browser session (below).
      RefreshToken: (_ctx: unknown, _token: unknown, client?: LegacyClient) =>
        isNative(client) ? config.oidcNativeRefreshIdleSeconds : config.refreshTokenTtlSeconds,
      Grant: (_ctx: unknown, _grant: unknown, client?: LegacyClient) =>
        isNative(client) ? config.oidcNativeGrantSeconds : config.refreshTokenTtlSeconds,
      Interaction: 600,
      Session: (_ctx, session) => sessionTtlSeconds(session as { loginTs?: number }),
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    // Every refresh issues a new token; presenting an old one revokes the whole grant (rotateRefreshToken below).
    // A refresh token ends with the browser session it came from, so logging out ends it too
    // (the default keeps offline_access tokens alive after logout). A native app is the exception: its
    // sign-in goes through the phone's browser, so tying it to that session would sign the app out
    // whenever the user signs out of another app there, or after 14 idle days. It ends instead with the
    // app's own sign-out (revocation), losing access, disabling, or the lifetimes above.
    expiresWithSession: async (ctx: { oidc: { client?: LegacyClient } }) => !isNative(ctx.oidc.client),
    // Refresh tokens rotate; a refused refresh must not spend the token (see refuseBeforeRotating).
    rotateRefreshToken: refuseBeforeRotating,
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
          // role and the names belong to the access token and /userinfo, not the ID token.
          // preferred_username stays the canonical login identifier (lowercase);
          // `name` is the display name, so apps can show the capitalization the user chose.
          return {
            sub: user.id,
            ...(use === "userinfo"
              ? { preferred_username: user.username, name: user.display_name || user.username, role: user.role }
              : {}),
          };
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
      return { type: "access", sid: (token as { sid?: string }).sid, username: user.username, display_name: user.display_name || user.username, role: user.role, scopes: user.scopes };
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
        defaultResource: async (ctx, client, oneOf) => {
          const { legacy_primary_resource: primary, legacy_default_resources: defaults } = client as LegacyClient;
          if (oneOf) {
            // A code or refresh token that covers several apps, redeemed without saying which: the client's
            // main app is not a guess. Any other client has to name one.
            const several = asList(oneOf);
            return primary && several.includes(primary) ? primary : oneOf;
          }
          // The authorization request named no resource. AppAuth can only send a map of parameters, so it cannot
          // send two; a client that registered defaults gets them, limited to the apps whose scopes it asked for.
          const asked = String((ctx.oidc?.params?.scope as string | undefined) ?? "").split(" ");
          const implied = new Set(resourcesForScopes(asked));
          const chosen = asList(defaults).filter((indicator) => implied.has(indicator));
          return chosen.length > 0 ? chosen : undefined;
        },
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
  patchRedirectUriMatching(provider);
  patchSessionIds(provider);
  strictAuthorizationRequests(provider);
  return provider;
}

/**
 * Called right before a refresh token is used up and replaced. The library spends the token first and only then
 * works out the access token, so a refresh that fails after that (a resource the user cannot have, one the grant
 * does not cover) leaves the client holding a token that is gone, and its next refresh is taken for theft and
 * revokes the whole grant. The client cannot know in advance what it may ask for, so those requests are refused
 * here, while the token is still good.
 *
 * Losing the app the sign-in is for (the primary one, or all of them) is not refused here: that ends the session
 * anyway, and the library says so with `invalid_grant`.
 */
async function refuseBeforeRotating(ctx: any): Promise<boolean> {
  const token = ctx.oidc?.entities?.RefreshToken;
  if (!token) return true;

  const granted = asList(token.resource);
  const primary = (ctx.oidc.client as LegacyClient).legacy_primary_resource;
  const requested = asList(ctx.oidc?.params?.resource);

  // Naming nothing, or several, only works for a grant of one app or a client with a main app.
  if (requested.length > 1) throw new errors.InvalidTarget("only a single resource indicator value must be requested during a refresh");
  if (requested.length === 0) {
    if (granted.length > 1 && !(primary && granted.includes(primary))) throw new errors.InvalidTarget("name the resource to refresh for");
    return true;
  }

  const [indicator] = requested;
  if (!granted.includes(indicator)) throw new errors.InvalidTarget("the grant does not cover this resource");
  const resource = RESOURCE_SERVERS[indicator];
  const user = await findUserById(String(token.accountId));
  // Without a main app every app the client is registered for is required: losing one ends the session (invalid_grant).
  const required = primary ? [primary] : resourcesForScopes([...clientScopes(ctx.oidc.client as { scope?: string })]);
  if (user && resource && !required.includes(indicator) && entitledResourceScopes(user, resource).length === 0) {
    throw new errors.InvalidTarget(`the account has no access to ${resource.audience}`);
  }
  return true;
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
 * The library matches redirect URIs exactly. A web app also has to be able to
 * come back to a preview deployment on a subdomain of a registered host
 * (legacy-auth#14), so a subdomain of a registered URI is allowed as well. The
 * library's own rule stays in place: it accepts a different loopback port for a
 * native client, and that is not something to lose.
 *
 * A test pins this: if a library upgrade renames either method, previews stop
 * signing in rather than an unregistered URI starting to work.
 */
function patchRedirectUriMatching(provider: Provider) {
  const proto = (provider as any).Client.prototype;
  const redirectUriMatches = proto.redirectUriAllowed;
  const postLogoutRedirectUriMatches = proto.postLogoutRedirectUriAllowed;
  proto.redirectUriAllowed = function (this: any, value: string) {
    return redirectUriMatches.call(this, value) || redirectUriAllowed(value, this.redirectUris);
  };
  proto.postLogoutRedirectUriAllowed = function (this: any, value: string) {
    return postLogoutRedirectUriMatches.call(this, value) || redirectUriAllowed(value, this.postLogoutRedirectUris);
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
