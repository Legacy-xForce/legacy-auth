import { config } from "../config.ts";

/** The token-pair body shared by password login, refresh and passkey login. */
export function tokenResponse(accessToken: string, refreshToken: string) {
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
  };
}
