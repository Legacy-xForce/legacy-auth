import { APP_AUDIENCES, type AppAudience, type UserRecord } from "../types.ts";

/**
 * A resource server (an app that accepts this service's access tokens).
 *
 * Resource indicators (RFC 8707) must be absolute URIs, so clients ask for
 * `urn:legacy:calendar`; the token's `aud` stays the plain app name that the
 * resource servers already pin (`calendar`, `tracker`).
 */
export type ResourceServer = {
  indicator: string;
  audience: AppAudience;
  /** Scopes the app defines. Read and write are separate on purpose: they only happen to be paired today. */
  scopes: readonly string[];
};

export const RESOURCE_SERVERS: Record<string, ResourceServer> = Object.fromEntries(
  APP_AUDIENCES.map((app) => {
    const indicator = `urn:legacy:${app}`;
    return [indicator, { indicator, audience: app, scopes: [`${app}.read`, `${app}.write`] } satisfies ResourceServer];
  })
);

/** Scopes that are not tied to a resource server. */
export const IDENTITY_SCOPES = ["openid", "profile", "offline_access"] as const;
export const ADMIN_SCOPE = "admin";

export const SUPPORTED_SCOPES: readonly string[] = [
  ...IDENTITY_SCOPES,
  ADMIN_SCOPE,
  ...Object.values(RESOURCE_SERVERS).flatMap((resource) => resource.scopes),
];

export const resourceForScope = (scope: string): ResourceServer | undefined =>
  Object.values(RESOURCE_SERVERS).find((resource) => resource.scopes.includes(scope));

/**
 * The scopes of `resource` this user may be granted. Today the user's boolean
 * app scope grants the app's read and write scopes together; this is the one
 * place to change when they can be granted separately.
 */
export function entitledResourceScopes(user: Pick<UserRecord, "scopes">, resource: ResourceServer): string[] {
  return user.scopes[resource.audience] ? [...resource.scopes] : [];
}

export const mayUseAdminScope = (user: Pick<UserRecord, "role">) => user.role === "admin";
