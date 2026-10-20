export const config = {
  port: Number(process.env.PORT ?? 4000),
  dbUrl: process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/legacy_auth",
  jwtSecret: process.env.JWT_SECRET ?? "replace-with-strong-secret",
  jwtPrivateKeyPem: process.env.JWT_PRIVATE_KEY,
  jwtKeyId: process.env.JWT_KEY_ID,
  // `iss` of every access token; resource servers pin it.
  jwtIssuer: process.env.JWT_ISSUER ?? "https://auth.legacy-group.tech",
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
};

function parseList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}
