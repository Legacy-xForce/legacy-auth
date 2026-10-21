import { createPrivateKey, createPublicKey } from "crypto";

// Secrets that must never sign tokens. The calendar's list, plus this service's own
// built-in fallback and the value `.env.example` ships with (a test keeps that in step).
export const FORBIDDEN_JWT_SECRETS = new Set(["replace-with-strong-secret", "super-secret-jwt-key", "changeme", "secret", "password"]);

// The public half of the signing key printed in `.env.example`. Anyone can read that
// file, so whoever copies it into production signs tokens with a key everyone has.
const PUBLISHED_EXAMPLE_KEY = { x: "z20qlPoldfyYZ4B7RS7mB1TW464sXHbKZjOdOHwVBR8", y: "byEn7E8Jwoft0Yo7aZyPNj-fwGoDEy8b5sRdCDJ8Zd0" };

/**
 * Problems that make a production start unsafe. A missing signing key would
 * silently become an ephemeral one that invalidates every token on restart, and
 * a placeholder secret lets anyone mint refresh tokens.
 */
export function productionConfigProblems(env: Record<string, string | undefined>): string[] {
  const problems: string[] = [];

  const secret = env.JWT_SECRET?.trim();
  if (!secret) {
    problems.push("JWT_SECRET is not set. Refusing to start with the built-in placeholder secret.");
  } else if (FORBIDDEN_JWT_SECRETS.has(secret)) {
    problems.push("JWT_SECRET is a well-known placeholder. Configure a unique, random secret.");
  }

  const pem = env.JWT_PRIVATE_KEY?.trim();
  if (!pem) {
    problems.push(
      "JWT_PRIVATE_KEY is not set. Without it a new signing key is generated on every start and every issued token stops verifying."
    );
  } else {
    try {
      // .env files often store newlines as literal \n (see keys.ts)
      const key = createPrivateKey(pem.replace(/\\n/g, "\n"));
      const curve = (key.asymmetricKeyDetails as { namedCurve?: string } | undefined)?.namedCurve;
      if (key.asymmetricKeyType !== "ec" || curve !== "prime256v1") {
        problems.push("JWT_PRIVATE_KEY must be an EC P-256 key (access tokens are signed with ES256).");
      } else {
        const jwk = createPublicKey(key).export({ format: "jwk" });
        if (jwk.x === PUBLISHED_EXAMPLE_KEY.x && jwk.y === PUBLISHED_EXAMPLE_KEY.y) {
          problems.push("JWT_PRIVATE_KEY is the example key from .env.example, which is public. Generate your own.");
        }
      }
    } catch {
      problems.push("JWT_PRIVATE_KEY is not a valid PEM private key.");
    }
  }

  return problems;
}

/** Throws when `env` describes a production start that would be unsafe; does nothing otherwise. */
export function assertBootConfig(env: Record<string, string | undefined> = process.env) {
  if (env.NODE_ENV !== "production") return;
  const problems = productionConfigProblems(env);
  if (problems.length > 0) {
    throw new Error(`Refusing to start in production:\n${problems.map((problem) => `  - ${problem}`).join("\n")}`);
  }
}
