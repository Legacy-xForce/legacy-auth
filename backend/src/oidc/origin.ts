import { config } from "../config.ts";

/** The issuer as a URL and its origin, parsed once for the whole OP (proxy, provider, clients, pages). */
export const issuerUrl = new URL(config.jwtIssuer);
export const issuerOrigin = issuerUrl.origin;
