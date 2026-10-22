import { SQL } from "bun";
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign } from "crypto";
import jwt from "jsonwebtoken";
import { bindServer, handleRequest } from "../src/app.ts";
import { createUserWithActive, updateUserScopes } from "../src/db.ts";
import { getJwks } from "../src/keys.ts";
import type { UserRole, UserScopes } from "../src/types.ts";

/** A second connection for assertions and for bending time in the database. */
export const testSql = new SQL(process.env.DATABASE_URL!);

export type TestApp = { url: string; stop: () => void };

export function startApp(): TestApp {
  const server = Bun.serve({ port: 0, fetch: handleRequest });
  bindServer(server);
  return { url: `http://localhost:${server.port}`, stop: () => server.stop(true) };
}

export type TestUser = { id: string; username: string; displayName?: string; password: string };

export async function createTestUser(
  options: { role?: UserRole; active?: boolean; scopes?: Partial<UserScopes>; password?: string; username?: string; displayName?: string } = {}
): Promise<TestUser> {
  const username = options.username ?? `u${randomBytes(5).toString("hex")}`;
  const password = options.password ?? `pw-${randomBytes(6).toString("hex")}`;
  const user = await createUserWithActive(username, password, options.active ?? true, {
    role: options.role ?? "user",
    displayName: options.displayName,
  });
  if (options.scopes) {
    await updateUserScopes(user.id, { calendar: false, tracker: false, ...options.scopes });
  }
  return { id: user.id, username: user.username, displayName: user.display_name, password };
}

export type CallOptions = {
  json?: unknown;
  form?: Record<string, string>;
  token?: string;
  headers?: Record<string, string>;
};

export type CallResult<T = any> = { status: number; headers: Headers; body: T };

/** Calls the app over HTTP and parses a JSON body when there is one. */
export async function call<T = any>(app: TestApp, method: string, path: string, options: CallOptions = {}): Promise<CallResult<T>> {
  const headers: Record<string, string> = { ...options.headers };
  let body: BodyInit | undefined;
  if (options.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(options.json);
  } else if (options.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(options.form);
  }
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  const response = await fetch(`${app.url}${path}`, { method, headers, body, redirect: "manual" });
  const text = await response.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // not JSON — keep the text
  }
  return { status: response.status, headers: response.headers, body: parsed as T };
}

export type TokenResponse = { access_token: string; refresh_token: string; expires_in: number; refresh_expires_in: number };

export async function login(app: TestApp, user: TestUser, extra: Record<string, unknown> = {}): Promise<CallResult<TokenResponse>> {
  return call(app, "POST", "/auth/login", { json: { username: user.username, password: user.password, ...extra } });
}

export async function loginOk(app: TestApp, user: TestUser, extra: Record<string, unknown> = {}): Promise<TokenResponse> {
  const result = await login(app, user, extra);
  if (result.status !== 200) throw new Error(`login failed: ${result.status} ${JSON.stringify(result.body)}`);
  return result.body;
}

/** Verifies an access token against the published JWKS, the way a resource server would. */
export function verifyWithJwks(token: string, options: jwt.VerifyOptions = {}): jwt.JwtPayload {
  const [jwk] = getJwks().keys;
  const key = createPublicKey({ key: jwk, format: "jwk" });
  return jwt.verify(token, key, { algorithms: ["ES256"], ...options }) as jwt.JwtPayload;
}

export const decode = (token: string) => jwt.decode(token, { complete: true })!;

/** An address a request appears to come from, when TRUST_PROXY is on. */
export const fromIp = (ip: string) => ({ "x-forwarded-for": ip });

export const b64url = (value: Buffer | string) => Buffer.from(value).toString("base64url");

/**
 * A software WebAuthn authenticator: real ECDSA keys and real authenticatorData,
 * so the server's signature, flag and counter checks run for real.
 */
export function createSoftwareAuthenticator(rpId = "auth.test.local") {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const credentialId = randomBytes(16).toString("base64url");
  let counter = 0;

  const clientData = (type: string, challenge: string) =>
    Buffer.from(JSON.stringify({ type, challenge, origin: `https://${rpId}`, crossOrigin: false }));

  return {
    credentialId,
    publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),

    registration(challenge: string) {
      return {
        id: credentialId,
        rawId: credentialId,
        deviceName: "Test passkey",
        response: {
          clientDataJSON: b64url(clientData("webauthn.create", challenge)),
          publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64url"),
        },
      };
    },

    assertion(challenge: string, options: { userPresent?: boolean; counter?: number; tamper?: boolean; audience?: string } = {}) {
      counter = options.counter ?? counter + 1;
      const authenticatorData = Buffer.concat([
        createHash("sha256").update(rpId).digest(),
        Buffer.from([options.userPresent === false ? 0x00 : 0x01]),
        Buffer.from([(counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]),
      ]);
      const data = clientData("webauthn.get", challenge);
      const signature = sign("sha256", Buffer.concat([authenticatorData, createHash("sha256").update(data).digest()]), privateKey);
      if (options.tamper) signature[signature.length - 1] ^= 0xff;
      return {
        id: credentialId,
        rawId: credentialId,
        ...(options.audience ? { audience: options.audience } : {}),
        response: {
          clientDataJSON: b64url(data),
          authenticatorData: b64url(authenticatorData),
          signature: b64url(signature),
        },
      };
    },
  };
}
