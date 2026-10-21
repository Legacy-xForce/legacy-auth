import jwt from "jsonwebtoken";
import { config } from "./config.ts";
import { createHash, randomUUID } from "crypto";
import { getPrivateKey, getPublicKey, getKid } from "./keys.ts";
import { APP_AUDIENCES, AppAudience, UserRole, UserScopes } from "./types.ts";

export type AccessTokenPayload = {
  sub: string;
  username: string;
  role: UserRole;
  scopes: UserScopes;
  type: "access";
  iss: string;
  aud?: AppAudience[];
};

export type RefreshTokenPayload = {
  sub: string;
  username: string;
  jti: string;
  type: "refresh";
  // The app the session was opened for; absent for sessions that cover every
  // app the user may use.
  app?: AppAudience;
};

export class AudienceError extends Error {
  constructor(message: string, readonly statusCode: 400 | 403) {
    super(message);
  }
}

/**
 * The `aud` of an access token: the requested app, or every app the user's
 * scopes allow when the client did not name one. Throws when the request
 * names an unknown app or one the user may not use.
 *
 * With `required`, a request that names no app is refused instead. That ends
 * the cross-app replay window of a token whose `aud` lists every app, but it
 * breaks clients that predate `audience`, so it is opt-in (REQUIRE_AUDIENCE).
 * Refreshing a session that was opened without an app is never `required`:
 * those sessions have no app to name and simply age out.
 */
export function resolveAudience(requested: unknown, scopes: UserScopes, options: { required?: boolean } = {}): AppAudience[] {
  if (requested === undefined || requested === null) {
    if (options.required) {
      throw new AudienceError(`audience is required and must be one of: ${APP_AUDIENCES.join(", ")}`, 400);
    }
    return APP_AUDIENCES.filter((app) => scopes[app]);
  }
  if (typeof requested !== "string" || !(APP_AUDIENCES as readonly string[]).includes(requested)) {
    throw new AudienceError(`audience must be one of: ${APP_AUDIENCES.join(", ")}`, 400);
  }
  const app = requested as AppAudience;
  if (!scopes[app]) {
    throw new AudienceError(`Account has no access to ${app}`, 403);
  }
  return [app];
}

export function signAccessToken(payload: { sub: string; username: string; role: UserRole; scopes: UserScopes; audience: AppAudience[] }) {
  return jwt.sign(
    {
      sub: payload.sub,
      username: payload.username,
      role: payload.role,
      scopes: payload.scopes,
      type: "access",
    },
    getPrivateKey(),
    {
      algorithm: "ES256",
      expiresIn: config.accessTokenTtlSeconds,
      keyid: getKid(),
      issuer: config.jwtIssuer,
      // A user with no app scopes still signs in to this service's console,
      // but gets a token no app accepts.
      ...(payload.audience.length > 0 ? { audience: payload.audience } : {}),
    }
  );
}

export function signRefreshToken(payload: { sub: string; username: string; app?: AppAudience }) {
  const jti = randomUUID();
  return {
    token: jwt.sign(
      {
        sub: payload.sub,
        username: payload.username,
        jti,
        type: "refresh",
        ...(payload.app ? { app: payload.app } : {}),
      },
      config.jwtSecret,
      {
        algorithm: "HS256",
        expiresIn: config.refreshTokenTtlSeconds,
      }
    ),
    jti,
  };
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, getPublicKey(), { algorithms: ["ES256"] }) as AccessTokenPayload;
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const payload = jwt.verify(token, config.jwtSecret) as RefreshTokenPayload;
  if (payload.type !== "refresh") {
    throw new Error("Invalid refresh token type");
  }
  return payload;
}

export function getRefreshTokenExpiresAt(): Date {
  return new Date(Date.now() + config.refreshTokenTtlSeconds * 1000);
}
