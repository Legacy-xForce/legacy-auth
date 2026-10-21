// Runs once before any test file is loaded. Modules read their configuration
// from the environment when first imported, so everything is set up here.
import { afterAll } from "bun:test";
import { SQL } from "bun";
import { generateKeyPairSync, randomBytes } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const adminUrl = process.env.TEST_DATABASE_URL;
if (!adminUrl) {
  throw new Error(
    "TEST_DATABASE_URL is not set. Point it at a throwaway Postgres server (one that can CREATE DATABASE), e.g.\n" +
      "  docker run --rm -p 54329:5432 -e POSTGRES_PASSWORD=postgres postgres:18-alpine\n" +
      "  TEST_DATABASE_URL=postgres://postgres:postgres@localhost:54329/postgres bun run test\n" +
      "Never use the production database: the suite creates and drops databases."
  );
}

// Each run gets its own database, so runs never see each other's rows.
const databaseName = `legacy_auth_test_${randomBytes(6).toString("hex")}`;
const admin = new SQL(adminUrl);
await admin.unsafe(`CREATE DATABASE "${databaseName}"`);

const databaseUrl = new URL(adminUrl);
databaseUrl.pathname = `/${databaseName}`;

const avatarDir = mkdtempSync(join(tmpdir(), "legacy-auth-avatars-"));

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl.toString();
process.env.JWT_SECRET = randomBytes(32).toString("hex");
process.env.JWT_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
process.env.JWT_ISSUER = "https://auth.test.local";
process.env.CORS_ALLOWED_ORIGINS = "https://calendar.test.local,https://tracker.test.local";
process.env.AVATAR_STORAGE_DIR = avatarDir;
process.env.LOGIN_MAX_FAILURES = "5";

const { initDatabase } = await import("../src/db.ts");
await initDatabase();

// One OpenID Provider for the whole run, like the one process a deployment has.
const { oidc } = await import("../src/oidc/index.ts");
await oidc.start();
if (!oidc.running) throw new Error("the OpenID Provider did not start; see the error logged above");

afterAll(async () => {
  await oidc.stop();
  // Close the pools first: dropping a database under open connections makes each of them log an error.
  const { sql } = await import("../src/db.ts");
  await sql.close({ timeout: 0 });
  const { testSql } = await import("./helpers.ts");
  await testSql.close({ timeout: 0 });
  rmSync(avatarDir, { recursive: true, force: true });
  // FORCE covers anything that is still connected.
  await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await admin.close({ timeout: 0 });
});
