import { getConnInfo } from "@hono/bun";
import { config } from "../config.ts";
import { isPrivateAddress } from "../throttle.ts";
import type { Ctx } from "./context.ts";

/** The Bun server passed as the second argument to `fetch`. */
export type PeerLookup = { requestIP(request: Request): { address: string } | null };

// The client address is resolved once per request and cached by Request so the
// wrapper (OIDC paths) and the Hono handlers see the same value.
const ipCache = new WeakMap<Request, string | null>();

/**
 * Resolve the peer address with Hono's Bun adapter (`getConnInfo`) and apply the
 * TRUST_PROXY rules. Cached per Request so every handler sees the same address.
 */
export function resolveClientIp(request: Request, server: PeerLookup): string | null {
  const cached = ipCache.get(request);
  if (cached !== undefined) return cached;

  let peer: string | null = null;
  try {
    // getConnInfo only reads `env` and `req.raw`, so a minimal context is enough
    // on the OIDC path which does not go through Hono's middleware.
    const info = getConnInfo({ env: server, req: { raw: request } } as any);
    peer = info.remote.address ?? null;
  } catch (error) {
    console.error("[conninfo] failed to read the client address", error);
  }

  // Forwarded headers are believed only from a proxy on a private address: a
  // client reaching the port directly could otherwise claim any IP.
  if (config.trustProxy && peer && isPrivateAddress(peer)) {
    const forwarded = (request.headers.get("x-forwarded-for") ?? "")
      .split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
    for (let i = forwarded.length - 1; i >= 0; i--) {
      if (!isPrivateAddress(forwarded[i])) {
        ipCache.set(request, forwarded[i]);
        return forwarded[i];
      }
    }
  }
  ipCache.set(request, peer);
  return peer;
}

export function clientIp(request: Request): string | null {
  return ipCache.get(request) ?? null;
}

export function throttleIp(c: Ctx): string | null {
  const ip = clientIp(c.req.raw);
  return ip && !isPrivateAddress(ip) ? ip : null;
}
