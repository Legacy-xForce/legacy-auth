// Declared before `config`, which uses it while the module initialises.
const DEFAULT_AUDIT_RETENTION_DAYS = 180;

export const config = {
  port: Number(process.env.PORT ?? 3000),
  dbUrl: process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/legacy_auth",
  jwtSecret: process.env.JWT_SECRET ?? "replace-with-strong-secret",
  jwtPrivateKeyPem: process.env.JWT_PRIVATE_KEY,
  jwtKeyId: process.env.JWT_KEY_ID,
  // `iss` of every access token; resource servers pin it.
  jwtIssuer: process.env.JWT_ISSUER ?? "https://auth.legacy-group.tech",
  // Whether login must name the app it is for. Off until every client sends
  // `audience`; see resolveAudience.
  requireAudience: process.env.REQUIRE_AUDIENCE === "true",
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 2592000),
  // How long a rotated refresh token may still be refreshed, so parallel
  // refreshes (or a retry after a lost response) don't sign the client out.
  refreshReuseGraceSeconds: Number(process.env.REFRESH_REUSE_GRACE_SECONDS ?? 30),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS ?? 300_000),
  avatarStorageDir: process.env.AVATAR_STORAGE_DIR ?? "./data/avatars",
  avatarMaxUploadBytes: Number(process.env.AVATAR_MAX_UPLOAD_BYTES ?? 8 * 1024 * 1024),
  frontendDistDir: process.env.FRONTEND_DIST_DIR ?? "../frontend/dist",
  // Android apps allowed to use this host's passkeys — see asset-links.ts.
  passkeyAndroidApps: parseList(process.env.PASSKEY_ANDROID_APPS),
  // Browser origins allowed to call the API — see cors.ts. Empty allows any.
  corsAllowedOrigins: parseList(process.env.CORS_ALLOWED_ORIGINS),
  // Failed sign-ins tolerated per username within the window — see throttle.ts.
  // Each client IP gets IP_FAILURE_MULTIPLIER times as many.
  loginMaxFailures: Number(process.env.LOGIN_MAX_FAILURES ?? 10),
  loginFailureWindowSeconds: Number(process.env.LOGIN_FAILURE_WINDOW_SECONDS ?? 900),
  // Behind a reverse proxy, take the client IP from X-Forwarded-For.
  trustProxy: process.env.TRUST_PROXY === "true",
  // How long auth_events rows are kept; 0 keeps them forever — see audit-retention.ts.
  auditRetentionDays: parseRetentionDays(process.env.AUDIT_RETENTION_DAYS),

  // ---- OpenID Provider (src/oidc) ----
  // Turn the whole OP off (its routes answer 404 and nothing is started) to roll back.
  oidcEnabled: process.env.OIDC_ENABLED !== "false",
  // Keys that sign the OP's cookies, newest first. Unset, one is derived from JWT_SECRET.
  oidcCookieKeys: parseList(process.env.OIDC_COOKIE_KEYS),
  // A browser session ends after this long without activity, or this long after sign-in, whichever is first.
  oidcSessionIdleSeconds: Number(process.env.OIDC_SESSION_IDLE_SECONDS ?? 14 * 86400),
  oidcSessionAbsoluteSeconds: Number(process.env.OIDC_SESSION_ABSOLUTE_SECONDS ?? 30 * 86400),
  // Native apps (a custom-scheme redirect) are not tied to the browser session. Their refresh token ends after
  // this long unused, and their grant this long after sign-in, whatever else happens. Web clients keep REFRESH_TOKEN_TTL_SECONDS.
  oidcNativeRefreshIdleSeconds: Number(process.env.OIDC_NATIVE_REFRESH_IDLE_SECONDS ?? 30 * 86400),
  oidcNativeGrantSeconds: Number(process.env.OIDC_NATIVE_GRANT_SECONDS ?? 180 * 86400),
  // How long a client's previous secret keeps working after rotate-secret.
  oidcSecretRotationGraceSeconds: Number(process.env.OIDC_SECRET_ROTATION_GRACE_SECONDS ?? 86400),
  // Back-channel logout deliveries that fail are retried after these delays, then given up.
  oidcBackchannelRetryDelaysMs: parseNumberList(process.env.OIDC_BACKCHANNEL_RETRY_DELAYS_MS, [5_000, 30_000, 120_000, 600_000, 3_600_000]),
  oidcBackchannelPollMs: Number(process.env.OIDC_BACKCHANNEL_POLL_MS ?? 2_000),
  // Whether back-channel logout may target localhost and private networks. Off in
  // production, where it would let a registered URI aim the server at internal services.
  oidcAllowInternalBackchannel: process.env.OIDC_ALLOW_INTERNAL_BACKCHANNEL
    ? process.env.OIDC_ALLOW_INTERNAL_BACKCHANNEL === "true"
    : process.env.NODE_ENV !== "production",
};

function parseNumberList(value: string | undefined, fallback: number[]): number[] {
  const parsed = parseList(value).map(Number);
  return parsed.length > 0 && parsed.every((n) => Number.isFinite(n) && n >= 0) ? parsed : fallback;
}

/** A whole number of days >= 0; anything else falls back to the default rather than pruning on a typo. */
export function parseRetentionDays(value: string | undefined): number {
  if (value === undefined || value.trim() === "") return DEFAULT_AUDIT_RETENTION_DAYS;
  const days = Number(value);
  if (!Number.isInteger(days) || days < 0) {
    console.warn(`[config] AUDIT_RETENTION_DAYS="${value}" is not a whole number of days; using ${DEFAULT_AUDIT_RETENTION_DAYS}`);
    return DEFAULT_AUDIT_RETENTION_DAYS;
  }
  return days;
}

function parseList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}
