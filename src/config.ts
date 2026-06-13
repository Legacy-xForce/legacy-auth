export const config = {
  port: Number(process.env.PORT ?? 4000),
  dbUrl: process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/legacy_auth",
  jwtSecret: process.env.JWT_SECRET ?? "replace-with-strong-secret",
  jwtPrivateKeyPem: process.env.JWT_PRIVATE_KEY,
  jwtKeyId: process.env.JWT_KEY_ID,
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 2592000),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS ?? 300_000),
  bcryptSaltRounds: Number(process.env.BCRYPT_SALT_ROUNDS ?? 12),
};
