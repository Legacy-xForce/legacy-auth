import { createServer, type Server } from "node:http";
import { createHash, randomBytes } from "crypto";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { config } from "../src/config.ts";
import { createClient, setClientDisabled, validateClientFields, type ClientFields } from "../src/oidc/clients.ts";
import { call, type TestApp, type TestUser } from "./helpers.ts";

export const ISSUER = process.env.JWT_ISSUER!;
export const ISSUER_ORIGIN = new URL(ISSUER).origin;

export const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

export const basicAuth = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

export type TestClient = { id: string; secret: string | null; redirect: string; logoutRedirect: string | null };

/** Registers a client with a unique id. Confidential unless `isPublic`. */
export async function registerClient(
  overrides: Partial<ClientFields> & { id?: string; disabled?: boolean } = {}
): Promise<TestClient> {
  const id = overrides.id ?? `t-${randomBytes(5).toString("hex")}`;
  const isPublic = overrides.is_public ?? false;
  const redirect = overrides.redirect_uris?.[0] ?? (isPublic ? "com.test.app:/callback" : `https://${id}.test.local/auth/callback`);
  const fields = validateClientFields({
    name: `Test ${id}`,
    is_public: isPublic,
    redirect_uris: [redirect],
    post_logout_redirect_uris: overrides.post_logout_redirect_uris ?? (isPublic ? [] : [`https://${id}.test.local/`]),
    backchannel_logout_uri: overrides.backchannel_logout_uri ?? null,
    allowed_scopes: overrides.allowed_scopes ?? ["openid", "profile", "calendar.read", "calendar.write", "tracker.read", "tracker.write", "offline_access"],
  });
  const { client, secret } = await createClient(id, fields, { disabled: overrides.disabled });
  return { id: client.client_id, secret, redirect, logoutRedirect: fields.post_logout_redirect_uris[0] ?? null };
}

export { setClientDisabled };

/** The interaction a flow stopped at, waiting for the user to sign in. */
export type Interaction = { uid: string };

export type AuthorizeResult = {
  /** Set when the flow reached the client's redirect URI. */
  redirect?: URL;
  /** Set when the flow stopped at a login screen. */
  interaction?: Interaction;
  /** The last response, for tests that expect an error page. */
  response: Response;
  trail: string[];
};

/** Just enough of a browser: cookies, manual redirects, and the issuer's public name mapped to the test server. */
export class Browser {
  jar = new Map<string, string>();
  setCookies: string[] = [];

  constructor(public app: TestApp) {}

  cookie(name: string) {
    return this.jar.get(name);
  }

  private absorb(response: Response) {
    for (const raw of response.headers.getSetCookie()) {
      this.setCookies.push(raw);
      const [pair] = raw.split(";");
      const index = pair.indexOf("=");
      const name = pair.slice(0, index);
      const value = pair.slice(index + 1);
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(raw) || value === "") this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  /** Where a Location from the provider really points in the test setup. */
  local(location: string): string {
    if (location.startsWith(ISSUER_ORIGIN)) return this.app.url + location.slice(ISSUER_ORIGIN.length);
    if (location.startsWith("/")) return this.app.url + location;
    return location;
  }

  async request(url: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    const cookie = [...this.jar].map(([name, value]) => `${name}=${value}`).join("; ");
    if (cookie) headers.set("cookie", cookie);
    const response = await fetch(this.local(url), { ...init, headers, redirect: "manual" });
    this.absorb(response);
    return response;
  }

  /**
   * The form of a page that submits itself on load (the provider's form_post pages), as the
   * browser's script would. Returns null for any other response.
   */
  private async autoSubmitForm(response: Response): Promise<{ action: string; fields: Record<string, string> } | null> {
    if (response.status !== 200 || !(response.headers.get("content-type") ?? "").includes("html")) return null;
    const html = await response.clone().text();
    if (!html.includes("document.forms[0].submit()")) return null;
    const action = html.match(/<form method="post" action="([^"]*)"/)?.[1];
    if (!action) return null;
    const unescape = (value: string) => value.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#x27;/g, "'");
    const fields: Record<string, string> = {};
    for (const [, name, value] of html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)"/g)) fields[name] = unescape(value);
    return { action: unescape(action), fields };
  }

  /** Follows redirects until the client's redirect URI, a login screen, or a dead end. */
  async follow(first: Response, redirectUri: string): Promise<AuthorizeResult> {
    let response = first;
    const trail: string[] = [];
    for (let hop = 0; hop < 15; hop++) {
      const location = response.headers.get("location");
      if (!location) {
        const form = await this.autoSubmitForm(response);
        if (!form) return { response, trail };
        trail.push(`form post to ${form.action}`);
        response = await this.request(form.action, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(form.fields),
        });
        continue;
      }
      trail.push(`${response.status} ${location.length > 90 ? `${location.slice(0, 90)}…` : location}`);
      if (location.startsWith(redirectUri)) return { redirect: new URL(location), response, trail };
      const next = await this.request(location);
      const uid = new URL(this.local(location)).pathname.match(/^\/interaction\/([\w-]+)$/)?.[1];
      if (uid && next.status === 200) {
        trail.push(`200 login screen for ${uid}`);
        return { interaction: { uid }, response: next, trail };
      }
      response = next;
    }
    return { response, trail };
  }

  async authorize(
    client: TestClient,
    options: { scope?: string; resource?: string | null; challenge: string; prompt?: string | null; state?: string; nonce?: string; extra?: Record<string, string> }
  ): Promise<AuthorizeResult> {
    const query = new URLSearchParams({
      client_id: client.id,
      redirect_uri: client.redirect,
      response_type: "code",
      scope: options.scope ?? "openid profile calendar.read calendar.write offline_access",
      code_challenge: options.challenge,
      code_challenge_method: "S256",
      state: options.state ?? "state-1",
      nonce: options.nonce ?? "nonce-1",
      ...options.extra,
    });
    // refresh tokens need prompt=consent (OIDC Core 11); the consent step is automatic, so users never see it
    if (options.prompt !== null) query.set("prompt", options.prompt ?? "consent");
    const resource = options.resource === undefined ? "urn:legacy:calendar" : options.resource;
    if (resource) query.set("resource", resource);
    return this.follow(await this.request(`${ISSUER_ORIGIN}/authorize?${query}`), client.redirect);
  }

  /** Submits the login form of an interaction and follows on to the client. */
  async signIn(interaction: Interaction, user: Pick<TestUser, "username" | "password">, client: TestClient): Promise<AuthorizeResult> {
    const result = await this.interactionCall(interaction.uid, "login", { username: user.username, password: user.password });
    if (result.status !== 200) throw new Error(`login failed: ${result.status} ${JSON.stringify(result.body)}`);
    return this.follow(new Response(null, { status: 303, headers: { location: result.body.redirect } }), client.redirect);
  }

  /** A JSON call to the interaction API, sent the way the sign-in page sends it. */
  async interactionCall(uid: string, action: string, body: unknown, headers: Record<string, string> = {}) {
    const response = await this.request(`${ISSUER_ORIGIN}/interaction/${uid}/${action}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ISSUER_ORIGIN, ...headers },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: any = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      // not JSON
    }
    return { status: response.status, headers: response.headers, body: parsed };
  }

  /** The JSON the sign-in page loads for an interaction. */
  async interactionDetails(uid: string): Promise<{ status: number; body: any }> {
    const response = await this.request(`${ISSUER_ORIGIN}/interaction/${uid}/details`);
    return { status: response.status, body: await response.json().catch(() => null) };
  }

  /** Presses "Back" on the no-access page and follows on to the client. */
  async leave(interaction: Interaction, client: TestClient): Promise<AuthorizeResult> {
    const result = await this.interactionCall(interaction.uid, "abort", {});
    if (result.status !== 200) throw new Error(`abort failed: ${result.status} ${JSON.stringify(result.body)}`);
    return this.follow(new Response(null, { status: 303, headers: { location: result.body.redirect } }), client.redirect);
  }

  /** The whole dance: authorize, sign in if asked to, and arrive at the redirect URI. */
  async flow(client: TestClient, user: Pick<TestUser, "username" | "password">, options: Parameters<Browser["authorize"]>[1]): Promise<AuthorizeResult> {
    let result = await this.authorize(client, options);
    if (result.interaction) result = await this.signIn(result.interaction, user, client);
    return result;
  }
}

export type TokenResult = { status: number; headers: Headers; body: any };

export async function tokenRequest(app: TestApp, body: Record<string, string>, authorization?: string): Promise<TokenResult> {
  return call(app, "POST", "/token", { form: body, headers: authorization ? { authorization } : {} });
}

/** Redeems the code at a redirect URI. */
export async function redeem(app: TestApp, client: TestClient, redirect: URL, verifier: string): Promise<TokenResult> {
  const code = redirect.searchParams.get("code");
  if (!code) throw new Error(`no code in ${redirect}`);
  return tokenRequest(
    app,
    { grant_type: "authorization_code", code, redirect_uri: client.redirect, code_verifier: verifier, ...(client.secret ? {} : { client_id: client.id }) },
    client.secret ? basicAuth(client.id, client.secret) : undefined
  );
}

export const refreshRequest = (app: TestApp, client: TestClient, refreshToken: string) =>
  tokenRequest(app, { grant_type: "refresh_token", refresh_token: refreshToken, ...(client.secret ? {} : { client_id: client.id }) }, client.secret ? basicAuth(client.id, client.secret) : undefined);

/** Signs in and returns the tokens of a first, complete flow. */
export async function signInAndRedeem(
  app: TestApp,
  browser: Browser,
  client: TestClient,
  user: Pick<TestUser, "username" | "password">,
  options: Partial<Parameters<Browser["authorize"]>[1]> = {}
) {
  const { verifier, challenge } = pkce();
  const result = await browser.flow(client, user, { challenge, ...options });
  if (!result.redirect) throw new Error(`flow did not reach the client: ${result.trail.join(" | ")}`);
  const tokens = await redeem(app, client, result.redirect, verifier);
  return { tokens, redirect: result.redirect, verifier, trail: result.trail };
}

/** A stand-in for an app's back-channel logout endpoint; fails the first `failFirst` calls. */
export type BackchannelStub = { url: string; hits: { body: string; at: number }[]; stop(): void };

export async function startBackchannelStub(options: { failFirst?: number; status?: number } = {}): Promise<BackchannelStub> {
  const hits: BackchannelStub["hits"] = [];
  let failures = options.failFirst ?? 0;
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      hits.push({ body, at: Date.now() });
      if (failures > 0) {
        failures--;
        res.statusCode = 500;
      } else {
        res.statusCode = options.status ?? 200;
      }
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}/backchannel-logout`,
    hits,
    stop: () => {
      server.close();
      server.closeAllConnections?.();
    },
  };
}

/** Points the sign-in page at a stub index.html so GET /interaction/:uid has something to serve. */
export function useStubFrontend(): () => void {
  const dir = mkdtempSync(join(tmpdir(), "legacy-auth-ui-"));
  writeFileSync(join(dir, "index.html"), "<!doctype html><title>stub</title><div id=app></div>");
  const previous = config.frontendDistDir;
  config.frontendDistDir = dir;
  return () => {
    config.frontendDistDir = previous;
    rmSync(dir, { recursive: true, force: true });
  };
}
