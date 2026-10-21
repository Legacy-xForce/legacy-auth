import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "fs";
import { tmpdir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { assertBootConfig, FORBIDDEN_JWT_SECRETS, productionConfigProblems } from "../src/boot-checks.ts";
import { parseRetentionDays } from "../src/config.ts";

const backendDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const pem = (type: "ec" | "rsa", options: object = {}) =>
  (generateKeyPairSync(type as any, options as any).privateKey.export({ type: "pkcs8", format: "pem" }) as string);

const goodKey = pem("ec", { namedCurve: "P-256" });
const goodEnv = { NODE_ENV: "production", JWT_SECRET: "a-long-random-secret-nobody-guesses", JWT_PRIVATE_KEY: goodKey };

describe("productionConfigProblems", () => {
  test("accepts a unique secret and an EC P-256 key", () => {
    expect(productionConfigProblems(goodEnv)).toEqual([]);
  });

  test("accepts a key whose newlines were stored as literal \\n (a .env habit)", () => {
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: goodKey.replace(/\n/g, "\\n") })).toEqual([]);
  });

  test("refuses a missing JWT_SECRET", () => {
    expect(productionConfigProblems({ ...goodEnv, JWT_SECRET: undefined }).join("\n")).toContain("JWT_SECRET is not set");
    expect(productionConfigProblems({ ...goodEnv, JWT_SECRET: "   " }).join("\n")).toContain("JWT_SECRET is not set");
  });

  test.each([...FORBIDDEN_JWT_SECRETS])("refuses the placeholder secret %p", (secret) => {
    expect(productionConfigProblems({ ...goodEnv, JWT_SECRET: secret }).join("\n")).toContain("well-known placeholder");
  });

  test("includes this service's own built-in default among the placeholders", () => {
    expect(FORBIDDEN_JWT_SECRETS.has("replace-with-strong-secret")).toBe(true);
  });

  test("refuses a missing signing key, explaining the consequence", () => {
    const problems = productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: undefined });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("JWT_PRIVATE_KEY is not set");
    expect(problems[0]).toContain("every issued token");
  });

  test("refuses a key that is not PEM", () => {
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: "not a key" }).join("\n")).toContain("not a valid PEM");
  });

  test("refuses an RSA key and an EC key on the wrong curve", () => {
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: pem("rsa", { modulusLength: 2048 }) }).join("\n")).toContain("EC P-256");
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: pem("ec", { namedCurve: "P-384" }) }).join("\n")).toContain("EC P-256");
  });

  test("reports every problem at once", () => {
    expect(productionConfigProblems({ NODE_ENV: "production" })).toHaveLength(2);
  });
});

describe("the values .env.example ships with", () => {
  // Read from the file itself, so editing the example cannot quietly reopen the hole.
  const example = Object.fromEntries(
    readFileSync(join(backendDir, ".env.example"), "utf8")
      .split("\n")
      .filter((line) => /^[A-Z_]+=/.test(line))
      .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)])
  );

  test("the example secret is refused in production", () => {
    expect(example.JWT_SECRET).toBeString();
    expect(productionConfigProblems({ ...goodEnv, JWT_SECRET: example.JWT_SECRET }).join("\n")).toContain("well-known placeholder");
  });

  test("the example signing key is refused in production, however its newlines are written", () => {
    expect(example.JWT_PRIVATE_KEY).toContain("BEGIN PRIVATE KEY");
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: example.JWT_PRIVATE_KEY }).join("\n")).toContain("example key from .env.example");
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: example.JWT_PRIVATE_KEY.replace(/\\n/g, "\n") }).join("\n")).toContain("example key from .env.example");
  });

  test("copying .env.example as it is into production does not boot", () => {
    expect(() => assertBootConfig({ NODE_ENV: "production", JWT_SECRET: example.JWT_SECRET, JWT_PRIVATE_KEY: example.JWT_PRIVATE_KEY })).toThrow(/Refusing to start in production/);
  });

  test("a freshly generated key is not mistaken for it", () => {
    expect(productionConfigProblems({ ...goodEnv, JWT_PRIVATE_KEY: pem("ec", { namedCurve: "P-256" }) })).toEqual([]);
  });
});

describe("assertBootConfig", () => {
  test("does nothing outside production, so development keeps its defaults", () => {
    expect(() => assertBootConfig({})).not.toThrow();
    expect(() => assertBootConfig({ NODE_ENV: "development" })).not.toThrow();
    expect(() => assertBootConfig({ NODE_ENV: "test" })).not.toThrow();
  });

  test("throws in production, naming each problem", () => {
    expect(() => assertBootConfig({ NODE_ENV: "production" })).toThrow(/Refusing to start in production[\s\S]*JWT_SECRET[\s\S]*JWT_PRIVATE_KEY/);
  });

  test("passes a correct production environment", () => {
    expect(() => assertBootConfig(goodEnv)).not.toThrow();
  });
});

describe("parseRetentionDays", () => {
  test("defaults to 180 days", () => {
    expect(parseRetentionDays(undefined)).toBe(180);
    expect(parseRetentionDays("")).toBe(180);
  });

  test("accepts whole numbers, including 0 (keep forever)", () => {
    expect(parseRetentionDays("30")).toBe(30);
    expect(parseRetentionDays("0")).toBe(0);
  });

  test.each(["abc", "-5", "1.5", "NaN", "10d"])("falls back to the default for %p instead of pruning on a typo", (value) => {
    expect(parseRetentionDays(value)).toBe(180);
  });
});

/** Starts the real entry point in a child process. */
function spawnServer(env: Record<string, string | undefined>) {
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries({ ...process.env, ...env })) {
    if (value !== undefined) cleaned[key] = value;
  }
  return Bun.spawn(["bun", "run", "src/index.ts"], { cwd: backendDir, env: cleaned, stdout: "pipe", stderr: "pipe" });
}

async function freePort(): Promise<number> {
  const probe = Bun.serve({ port: 0, fetch: () => new Response("") });
  const port = probe.port!;
  await probe.stop(true);
  return port;
}

describe("the real entry point", () => {
  test("refuses to boot in production without secrets, before generating an ephemeral key", async () => {
    const child = spawnServer({ NODE_ENV: "production", JWT_SECRET: undefined, JWT_PRIVATE_KEY: undefined, PORT: String(await freePort()) });
    const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
    expect(code).not.toBe(0);
    expect(stderr).toContain("Refusing to start in production");
    expect(stderr).toContain("JWT_SECRET");
    expect(stderr).toContain("JWT_PRIVATE_KEY");
    // keys.ts must never have run: that warning means a throwaway key was generated
    expect(stderr).not.toContain("ephemeral");
  }, 20_000);

  test("refuses a placeholder secret in production even when a key is set", async () => {
    const child = spawnServer({ ...goodEnv, JWT_SECRET: "replace-with-strong-secret", PORT: String(await freePort()) });
    const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
    expect(code).not.toBe(0);
    expect(stderr).toContain("well-known placeholder");
  }, 20_000);

  test("shuts down cleanly on SIGTERM, leaving no socket behind", async () => {
    const scratch = mkdtempSync(join(tmpdir(), "legacy-auth-shutdown-"));
    const port = await freePort();
    const child = spawnServer({ ...goodEnv, NODE_ENV: "development", PORT: String(port), TMPDIR: scratch });
    try {
      let up = false;
      for (let attempt = 0; attempt < 100 && !up; attempt++) {
        try {
          up = (await fetch(`http://localhost:${port}/.well-known/openid-configuration`)).ok;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      expect(up).toBe(true);
      // while it runs, its private socket directory exists
      expect(readdirSync(scratch).filter((name) => name.startsWith("legacy-auth-oidc-"))).toHaveLength(1);

      child.kill("SIGTERM");
      expect(await child.exited).toBe(0);
      expect(readdirSync(scratch).filter((name) => name.startsWith("legacy-auth-oidc-"))).toHaveLength(0);
    } finally {
      child.kill();
      rmSync(scratch, { recursive: true, force: true });
    }
  }, 30_000);

  test("boots in production with real secrets and serves its key set", async () => {
    const port = await freePort();
    const child = spawnServer({ ...goodEnv, PORT: String(port), CORS_ALLOWED_ORIGINS: "https://calendar.test.local" });
    try {
      let jwks: any = null;
      for (let attempt = 0; attempt < 100 && !jwks; attempt++) {
        try {
          const response = await fetch(`http://localhost:${port}/.well-known/jwks.json`);
          if (response.ok) jwks = await response.json();
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      expect(jwks?.keys?.[0]?.alg).toBe("ES256");
    } finally {
      child.kill();
      await child.exited;
    }
  }, 30_000);
});
