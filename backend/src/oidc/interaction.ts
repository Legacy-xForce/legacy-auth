import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import { Hono, type Context, type Next } from "hono";
import type Provider from "oidc-provider";
import { config } from "../config.ts";
import { findUserById } from "../db.ts";
import { generateLoginOptions, verifyAssertion } from "../passkey.ts";
import { isPrivateAddress, recordFailure, retryAfterSeconds, throttleKeys } from "../throttle.ts";
import { normalizeUsername } from "../usernames.ts";
import { auditOidc } from "./audit.ts";
import { checkPasswordLogin } from "./credentials.ts";
import { issuerOrigin } from "./origin.ts";
import { errorPage, STATIC_PAGE_CSP } from "./pages.ts";
import { ACR_BASIC } from "./provider.ts";
import { ADMIN_SCOPE, entitledResourceScopes, mayUseAdminScope, RESOURCE_SERVERS } from "./scopes.ts";

/**
 * The sign-in screens the provider redirects to (`/interaction/:uid`).
 *
 * The page itself is the console's Vue app (its /interaction/:uid route); this
 * Hono app answers the page's JSON calls and finishes the interaction. Consent is
 * not a screen: every client is a first-party app, so a request is granted
 * automatically when the signed-in user may have what it asks for, and refused
 * with `access_denied` when not (the OP's version of `403`).
 *
 * A client can name a primary resource (clients.ts): it is the one app the sign-in
 * is for. A user who may not have the client's other resources still signs in, and
 * gets the primary app's grant without them. Without one, every app it asks for is required.
 */

const UID = /^[\w-]{10,100}$/;
const MAX_BODY_BYTES = 16 * 1024;

type Details = Awaited<ReturnType<Provider["interactionDetails"]>>;

type InteractionEnv = {
  // The library reads cookies from the Node request and may set them on the Node
  // response; Hono owns everything about the HTTP answer returned to the browser.
  Bindings: { nodeReq: IncomingMessage; nodeRes: ServerResponse; provider: Provider };
  Variables: { details: Details; body: Record<string, any> };
};
type ICtx = Context<InteractionEnv>;

async function readJson(c: ICtx): Promise<Record<string, any> | null> {
  const stream = c.env.nodeReq;
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += (chunk as Buffer).length;
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

/** The client address the front end vouches for (it overwrites the header on every request). */
const clientIp = (c: ICtx) => c.req.header("x-client-ip") ?? null;

/** The address to count failures against, or null when it is just a proxy's. */
const throttleIp = (c: ICtx) => {
  const ip = clientIp(c);
  return ip && !isPrivateAddress(ip) ? ip : null;
};

/**
 * Login CSRF defence for the JSON calls. A browser always sends `Origin` on a
 * POST, and a page on another origin cannot make it match ours; `Sec-Fetch-Site`
 * is a second check where the browser provides it. The interaction cookie
 * (SameSite=Lax, bound to this uid) is a third line, and a JSON body means the
 * request is not a "simple" cross-site one.
 */
function sameOriginJson(c: ICtx): string | null {
  if (c.req.header("origin") !== issuerOrigin) return "Cross-origin request refused";
  const site = c.req.header("sec-fetch-site");
  if (site && site !== "same-origin") return "Cross-site request refused";
  if (!(c.req.header("content-type") ?? "").toLowerCase().startsWith("application/json")) return "Content-Type must be application/json";
  return null;
}

const expired = (c: ICtx, wantsHtml: boolean) =>
  wantsHtml
    ? c.html(errorPage({ error: "interaction_expired", error_description: "This sign-in link has expired or was already used" }), 400, {
        "content-security-policy": STATIC_PAGE_CSP,
      })
    : c.json({ error: "interaction_expired" }, 410);

export function createInteractionApp(provider: Provider): Hono<InteractionEnv> {
  const app = new Hono<InteractionEnv>();

  app.notFound((c) => c.json({ error: "Not found" }, 404));

  // The old path regex refused malformed uids with a 404. Hono's `:uid` matches
  // any segment, so validate it once as param middleware.
  const validUid = async (c: ICtx, next: Next) => {
    if (!UID.test(c.req.param("uid") ?? "")) return c.json({ error: "Not found" }, 404);
    await next();
  };
  app.use("/interaction/:uid", validUid);
  app.use("/interaction/:uid/*", validUid);

  async function detailsFor(c: ICtx, wantsHtml: boolean): Promise<Details | Response> {
    try {
      const details = await provider.interactionDetails(c.env.nodeReq, c.env.nodeRes);
      // The cookie must belong to the interaction in the URL, not to some other one.
      if (details.uid === c.req.param("uid")) return details;
    } catch {
      // no cookie, or the interaction expired
    }
    return expired(c, wantsHtml);
  }

  const loadDetails = (wantsHtml: boolean) => async (c: ICtx, next: Next) => {
    const result = await detailsFor(c, wantsHtml);
    if (result instanceof Response) return result;
    c.set("details", result);
    await next();
  };

  /** Ends the interaction by sending the user back to the client with an error. */
  const refuse = (c: ICtx, description: string) =>
    provider.interactionResult(c.env.nodeReq, c.env.nodeRes, { error: "access_denied", error_description: description }, { mergeWithLastSubmission: false });

  /** Grants what the client asked for if the signed-in user may have it; otherwise returns the refusal's redirect. */
  async function consent(c: ICtx, details: Details): Promise<string> {
    const accountId = details.session?.accountId;
    const user = accountId ? await findUserById(accountId) : null;
    if (!user || !user.active) return refuse(c, "The account is not available");

    const prompt = details.prompt.details as {
      missingOIDCScope?: string[];
      missingOIDCClaims?: string[];
      missingResourceScopes?: Record<string, string[]>;
    };

    const deny = async (reason: string) => {
      await auditOidc({ event: "oidc.consent", success: false, userId: user.id, detail: `${details.params.client_id}: ${reason}` });
      return refuse(c, reason);
    };

    if (prompt.missingOIDCScope?.includes(ADMIN_SCOPE) && !mayUseAdminScope(user)) return deny("The admin scope requires an admin account");

    const clientId = String(details.params.client_id);
    const client = (await (provider as any).Client.find(clientId)) as { legacy_primary_resource?: string } | undefined;
    if (!client) return deny("Unknown client");
    const primary = client.legacy_primary_resource;

    // Which of the requested apps the user may have. The others are left out of the request (and the grant)
    // when they are optional for this client, and end the sign-in when they are not.
    const left: string[] = [];
    const granted: [string, string[]][] = [];
    for (const [indicator, scopes] of Object.entries(prompt.missingResourceScopes ?? {})) {
      const resource = RESOURCE_SERVERS[indicator];
      if (!resource) return deny("Unknown resource");
      const entitled = entitledResourceScopes(user, resource);
      if (scopes.every((scope) => entitled.includes(scope))) {
        granted.push([indicator, scopes]);
      } else if (!primary || indicator === primary) {
        return deny(`The account has no access to ${resource.audience}`);
      } else {
        left.push(indicator);
      }
    }

    if (left.length > 0) {
      const omitted = new Set(left.flatMap((indicator) => RESOURCE_SERVERS[indicator].scopes));
      const params = details.params as Record<string, unknown>;
      const resources = (Array.isArray(params.resource) ? params.resource : [params.resource]).filter((entry) => typeof entry === "string") as string[];
      const kept = resources.filter((indicator) => !left.includes(indicator));
      if (kept.length === 0) return deny("The account has no access to any resource this sign-in asks for");
      // The sign-in resumes with these parameters: it must not ask again for what was left out.
      params.resource = kept.length === 1 ? kept[0] : kept;
      params.scope = String(params.scope ?? "").split(" ").filter((scope) => !omitted.has(scope)).join(" ");
      await (details as any).save((details as any).exp - Math.floor(Date.now() / 1000));
      await auditOidc({ event: "oidc.consent", success: true, userId: user.id, detail: `${clientId}: signed in without ${left.join(", ")}` });
    }

    const grant = details.grantId
      ? ((await provider.Grant.find(details.grantId)) ?? new provider.Grant({ accountId: user.id, client } as any))
      : new provider.Grant({ accountId: user.id, client } as any);

    if (prompt.missingOIDCScope?.length) grant.addOIDCScope(prompt.missingOIDCScope.join(" "));
    if (prompt.missingOIDCClaims?.length) grant.addOIDCClaims(prompt.missingOIDCClaims);
    for (const [indicator, scopes] of granted) grant.addResourceScope(indicator, scopes.join(" "));

    const grantId = await grant.save();
    return provider.interactionResult(c.env.nodeReq, c.env.nodeRes, { consent: { grantId } }, { mergeWithLastSubmission: true });
  }

  async function sendSpa(c: ICtx) {
    const index = Bun.file(join(config.frontendDistDir, "index.html"));
    if (!(await index.exists())) {
      return c.html(errorPage({ error: "temporarily_unavailable", error_description: "The sign-in page is not built" }), 503, {
        "content-security-policy": STATIC_PAGE_CSP,
      });
    }
    return c.html(await index.text(), 200, { "content-security-policy": "frame-ancestors 'none'" });
  }

  // The page: the Vue app for a login, a redirect for consent.
  app.get("/interaction/:uid", loadDetails(true), async (c) => {
    const details = c.var.details;
    if (details.prompt.name === "login") return sendSpa(c);
    if (details.prompt.name === "consent") {
      return c.newResponse(null, 303, { location: await consent(c, details), "cache-control": "no-store" });
    }
    return c.html(errorPage({ error: "invalid_request", error_description: "Unsupported interaction" }), 400, { "content-security-policy": STATIC_PAGE_CSP });
  });

  app.get("/interaction/:uid/details", loadDetails(false), async (c) => {
    const details = c.var.details;
    const client = await (provider as any).Client.find(String(details.params.client_id));
    return c.json({
      uid: c.req.param("uid"),
      prompt: details.prompt.name,
      client: { id: client?.clientId ?? null, name: client?.clientName ?? client?.clientId ?? null },
      login_hint: typeof details.params.login_hint === "string" ? details.params.login_hint : null,
    });
  });

  // Every POST action shares the CSRF check, the JSON body and the interaction details.
  const postSetup = async (c: ICtx, next: Next) => {
    const rejected = sameOriginJson(c);
    if (rejected) return c.json({ error: rejected }, 403);
    const body = await readJson(c);
    if (!body) return c.json({ error: "A JSON object body is required" }, 400);
    c.set("body", body);
    return loadDetails(false)(c, next);
  };
  app.use("/interaction/:uid/login", postSetup);
  app.use("/interaction/:uid/passkey/options", postSetup);
  app.use("/interaction/:uid/passkey/verify", postSetup);
  app.use("/interaction/:uid/abort", postSetup);

  app.post("/interaction/:uid/abort", async (c) => {
    return c.json({ redirect: await refuse(c, "The user cancelled the sign-in") });
  });

  const signInOnly = async (c: ICtx, next: Next) => {
    if (c.var.details.prompt.name !== "login") return c.json({ error: "This interaction is not asking for a sign-in" }, 409);
    await next();
  };
  app.use("/interaction/:uid/passkey/options", signInOnly);
  app.use("/interaction/:uid/passkey/verify", signInOnly);
  app.use("/interaction/:uid/login", signInOnly);

  const finish = async (c: ICtx, userId: string, amr: string[]) => {
    const redirect = await provider.interactionResult(
      c.env.nodeReq,
      c.env.nodeRes,
      { login: { accountId: userId, amr, acr: ACR_BASIC, remember: true } },
      { mergeWithLastSubmission: false }
    );
    return c.json({ redirect });
  };

  app.post("/interaction/:uid/passkey/options", async (c) => {
    const username = typeof c.var.body.username === "string" && c.var.body.username.trim() ? normalizeUsername(c.var.body.username) : undefined;
    return c.json(await generateLoginOptions(username));
  });

  app.post("/interaction/:uid/login", async (c) => {
    const username = normalizeUsername(c.var.body.username);
    const password = typeof c.var.body.password === "string" ? c.var.body.password : "";
    if (!username || !password || username.length > 200 || password.length > 1024) {
      return c.json({ error: "username and password are required" }, 400);
    }
    const result = await checkPasswordLogin(username, password, throttleIp(c));
    if (!result.ok) {
      await auditOidc({ event: "oidc.login", success: false, userId: result.userId, username, detail: result.status === 429 ? "throttled" : result.error });
      return c.json({ error: result.error }, result.status, result.retryAfter ? { "retry-after": String(result.retryAfter) } : {});
    }
    await auditOidc({ event: "oidc.login", success: true, userId: result.user.id, detail: "pwd" });
    return finish(c, result.user.id, ["pwd"]);
  });

  // passkey/verify: no username to count against, so failures are throttled per client address only
  app.post("/interaction/:uid/passkey/verify", async (c) => {
    const throttle = throttleKeys(throttleIp(c));
    const retryAfter = retryAfterSeconds(throttle);
    if (retryAfter !== null) {
      await auditOidc({ event: "oidc.login", success: false, detail: "passkey: throttled" });
      return c.json({ error: "Too many failed attempts, try again later" }, 429, { "retry-after": String(retryAfter) });
    }
    try {
      const { user } = await verifyAssertion(c.var.body as any);
      await auditOidc({ event: "oidc.login", success: true, userId: user.id, detail: "webauthn" });
      return await finish(c, user.id, ["webauthn"]);
    } catch (error: any) {
      const status = error?.statusCode || 401;
      if (status === 401) recordFailure(throttle);
      await auditOidc({ event: "oidc.login", success: false, detail: `passkey: ${error?.message ?? "verification failed"}` });
      return c.json({ error: error?.message || "Passkey verification failed" }, status);
    }
  });

  return app;
}
