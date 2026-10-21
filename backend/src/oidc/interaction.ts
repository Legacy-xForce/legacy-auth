import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import type Provider from "oidc-provider";
import { config } from "../config.ts";
import { findUserById } from "../db.ts";
import { generateLoginOptions, verifyAssertion } from "../passkey.ts";
import { isPrivateAddress, recordFailure, retryAfterSeconds, throttleKeys } from "../throttle.ts";
import { auditOidc } from "./audit.ts";
import { checkPasswordLogin } from "./credentials.ts";
import { ACR_BASIC } from "./provider.ts";
import { errorPage, STATIC_PAGE_CSP } from "./pages.ts";
import { ADMIN_SCOPE, entitledResourceScopes, mayUseAdminScope, RESOURCE_SERVERS } from "./scopes.ts";

/**
 * The sign-in screens the provider redirects to (`/interaction/:uid`).
 *
 * The page itself is the console's Vue app (its /interaction/:uid route); this
 * file answers the page's JSON calls and finishes the interaction. Consent is
 * not a screen: every client is a first-party app, so a request is granted
 * automatically when the signed-in user may have what it asks for, and refused
 * with `access_denied` when not (the OP's version of `403`).
 */

const UID = /^[\w-]{10,100}$/;
const MAX_BODY_BYTES = 16 * 1024;

type Details = Awaited<ReturnType<Provider["interactionDetails"]>>;

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", pragma: "no-cache", ...headers });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", pragma: "no-cache", ...headers });
  res.end(html);
}

async function readJson(req: IncomingMessage): Promise<Record<string, any> | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk as Buffer);
  }
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

const header = (req: IncomingMessage, name: string) => {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
};

/** The client address the front end vouches for (it overwrites the header on every request). */
const clientIp = (req: IncomingMessage) => header(req, "x-client-ip") ?? null;

/** The address to count failures against, or null when it is just a proxy's. */
const throttleIp = (req: IncomingMessage) => {
  const ip = clientIp(req);
  return ip && !isPrivateAddress(ip) ? ip : null;
};

/**
 * Login CSRF defence for the JSON calls. A browser always sends `Origin` on a
 * POST, and a page on another origin cannot make it match ours; `Sec-Fetch-Site`
 * is a second check where the browser provides it. The interaction cookie
 * (SameSite=Lax, bound to this uid) is a third line, and a JSON body means the
 * request is not a "simple" cross-site one.
 */
function sameOriginJson(req: IncomingMessage): string | null {
  const origin = header(req, "origin");
  if (origin !== new URL(config.jwtIssuer).origin) return "Cross-origin request refused";
  const site = header(req, "sec-fetch-site");
  if (site && site !== "same-origin") return "Cross-site request refused";
  if (!(header(req, "content-type") ?? "").toLowerCase().startsWith("application/json")) return "Content-Type must be application/json";
  return null;
}

async function sendSpa(res: ServerResponse) {
  const index = Bun.file(join(config.frontendDistDir, "index.html"));
  if (!(await index.exists())) {
    return sendHtml(res, 503, errorPage({ error: "temporarily_unavailable", error_description: "The sign-in page is not built" }), {
      "content-security-policy": STATIC_PAGE_CSP,
    });
  }
  sendHtml(res, 200, await index.text(), { "content-security-policy": "frame-ancestors 'none'" });
}

export function createInteractionHandler(provider: Provider) {
  const expired = (res: ServerResponse, wantsHtml: boolean) =>
    wantsHtml
      ? sendHtml(res, 400, errorPage({ error: "interaction_expired", error_description: "This sign-in link has expired or was already used" }), {
          "content-security-policy": STATIC_PAGE_CSP,
        })
      : send(res, 410, { error: "interaction_expired" });

  async function detailsFor(req: IncomingMessage, res: ServerResponse, uid: string, wantsHtml: boolean): Promise<Details | null> {
    try {
      const details = await provider.interactionDetails(req, res);
      // The cookie must belong to the interaction in the URL, not to some other one.
      if (details.uid === uid) return details;
    } catch {
      // no cookie, or the interaction expired
    }
    expired(res, wantsHtml);
    return null;
  }

  /** Ends the interaction by sending the user back to the client with an error. */
  async function refuse(req: IncomingMessage, res: ServerResponse, description: string): Promise<string> {
    return provider.interactionResult(req, res, { error: "access_denied", error_description: description }, { mergeWithLastSubmission: false });
  }

  /** Grants what the client asked for if the signed-in user may have it; otherwise returns the refusal's redirect. */
  async function consent(req: IncomingMessage, res: ServerResponse, details: Details): Promise<string> {
    const accountId = details.session?.accountId;
    const user = accountId ? await findUserById(accountId) : null;
    if (!user || !user.active) return refuse(req, res, "The account is not available");

    const prompt = details.prompt.details as {
      missingOIDCScope?: string[];
      missingOIDCClaims?: string[];
      missingResourceScopes?: Record<string, string[]>;
    };

    const deny = async (reason: string) => {
      await auditOidc({ event: "oidc.consent", success: false, userId: user.id, detail: `${details.params.client_id}: ${reason}` });
      return refuse(req, res, reason);
    };

    if (prompt.missingOIDCScope?.includes(ADMIN_SCOPE) && !mayUseAdminScope(user)) return deny("The admin scope requires an admin account");

    const clientId = String(details.params.client_id);
    const grant = details.grantId
      ? ((await provider.Grant.find(details.grantId)) ?? new provider.Grant({ accountId: user.id, clientId }))
      : new provider.Grant({ accountId: user.id, clientId });

    if (prompt.missingOIDCScope?.length) grant.addOIDCScope(prompt.missingOIDCScope.join(" "));
    if (prompt.missingOIDCClaims?.length) grant.addOIDCClaims(prompt.missingOIDCClaims);

    for (const [indicator, scopes] of Object.entries(prompt.missingResourceScopes ?? {})) {
      const resource = RESOURCE_SERVERS[indicator];
      if (!resource) return deny("Unknown resource");
      const entitled = entitledResourceScopes(user, resource);
      if (scopes.some((scope) => !entitled.includes(scope))) return deny(`The account has no access to ${resource.audience}`);
      grant.addResourceScope(indicator, scopes.join(" "));
    }

    const grantId = await grant.save();
    return provider.interactionResult(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
  }

  /** Returns true when the request was one of ours. */
  return async function handleInteraction(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
    const match = url.pathname.match(/^\/interaction\/([^/]+)(?:\/(.+))?$/);
    if (!match) return false;
    const [, uid, action = ""] = match;
    if (!UID.test(uid)) {
      send(res, 404, { error: "Not found" });
      return true;
    }
    const method = req.method ?? "GET";

    // The page: the Vue app for a login, a redirect for consent.
    if (action === "" && method === "GET") {
      const details = await detailsFor(req, res, uid, true);
      if (!details) return true;
      if (details.prompt.name === "login") {
        await sendSpa(res);
      } else if (details.prompt.name === "consent") {
        res.writeHead(303, { location: await consent(req, res, details), "cache-control": "no-store" });
        res.end();
      } else {
        sendHtml(res, 400, errorPage({ error: "invalid_request", error_description: "Unsupported interaction" }), { "content-security-policy": STATIC_PAGE_CSP });
      }
      return true;
    }

    if (action === "details" && method === "GET") {
      const details = await detailsFor(req, res, uid, false);
      if (!details) return true;
      const client = await (provider as any).Client.find(String(details.params.client_id));
      send(res, 200, {
        uid,
        prompt: details.prompt.name,
        client: { id: client?.clientId ?? null, name: client?.clientName ?? client?.clientId ?? null },
        login_hint: typeof details.params.login_hint === "string" ? details.params.login_hint : null,
      });
      return true;
    }

    if (method !== "POST" || !["login", "passkey/options", "passkey/verify", "abort"].includes(action)) {
      send(res, 404, { error: "Not found" });
      return true;
    }

    const rejected = sameOriginJson(req);
    if (rejected) {
      send(res, 403, { error: rejected });
      return true;
    }
    const body = await readJson(req);
    if (!body) {
      send(res, 400, { error: "A JSON object body is required" });
      return true;
    }
    const details = await detailsFor(req, res, uid, false);
    if (!details) return true;

    if (action === "abort") {
      send(res, 200, { redirect: await refuse(req, res, "The user cancelled the sign-in") });
      return true;
    }

    // Everything below signs the user in, which only makes sense for a login prompt.
    if (details.prompt.name !== "login") {
      send(res, 409, { error: "This interaction is not asking for a sign-in" });
      return true;
    }

    if (action === "passkey/options") {
      const username = typeof body.username === "string" && body.username.trim() ? body.username.trim() : undefined;
      send(res, 200, await generateLoginOptions(username));
      return true;
    }

    const finish = async (userId: string, amr: string[]) => {
      const redirect = await provider.interactionResult(
        req,
        res,
        { login: { accountId: userId, amr, acr: ACR_BASIC, remember: true } },
        { mergeWithLastSubmission: false }
      );
      send(res, 200, { redirect });
    };

    if (action === "login") {
      const username = typeof body.username === "string" ? body.username.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (!username || !password || username.length > 200 || password.length > 1024) {
        send(res, 400, { error: "username and password are required" });
        return true;
      }
      const result = await checkPasswordLogin(username, password, throttleIp(req));
      if (!result.ok) {
        await auditOidc({ event: "oidc.login", success: false, userId: result.userId, username, detail: result.status === 429 ? "throttled" : result.error });
        send(res, result.status, { error: result.error }, result.retryAfter ? { "retry-after": String(result.retryAfter) } : {});
        return true;
      }
      await auditOidc({ event: "oidc.login", success: true, userId: result.user.id, detail: "pwd" });
      await finish(result.user.id, ["pwd"]);
      return true;
    }

    // passkey/verify: no username to count against, so failures are throttled per client address only
    const throttle = throttleKeys(throttleIp(req));
    const retryAfter = retryAfterSeconds(throttle);
    if (retryAfter !== null) {
      await auditOidc({ event: "oidc.login", success: false, detail: "passkey: throttled" });
      send(res, 429, { error: "Too many failed attempts, try again later" }, { "retry-after": String(retryAfter) });
      return true;
    }
    try {
      const { user } = await verifyAssertion(body as any);
      await auditOidc({ event: "oidc.login", success: true, userId: user.id, detail: "webauthn" });
      await finish(user.id, ["webauthn"]);
    } catch (error: any) {
      const status = error?.statusCode || 401;
      if (status === 401) recordFailure(throttle);
      await auditOidc({ event: "oidc.login", success: false, detail: `passkey: ${error?.message ?? "verification failed"}` });
      send(res, status, { error: error?.message || "Passkey verification failed" });
    }
    return true;
  };
}
