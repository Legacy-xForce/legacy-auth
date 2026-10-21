import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * oidc-provider guards its outgoing requests against internal addresses by
 * hooking undici, which Bun does not use, so on Bun that guard silently does
 * nothing. The only request this service makes is back-channel logout to a URI
 * an admin registered; this module closes that gap.
 */

const V4_BLOCKS: [string, number][] = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, incl. cloud metadata services
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, incl. broadcast
];

function v4ToInt(address: string): number {
  return address.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

function inBlock(address: number, [base, bits]: [string, number]): boolean {
  const size = 2 ** (32 - bits);
  const start = v4ToInt(base);
  return address >= start && address < start + size;
}

/** Whether an IP literal is loopback, private, link-local, multicast or otherwise not a public host. */
export function isInternalAddress(address: string): boolean {
  const ip = address.replace(/^\[|\]$/g, "").toLowerCase();
  const family = isIP(ip);
  if (family === 4) return V4_BLOCKS.some((block) => inBlock(v4ToInt(ip), block));
  if (family === 6) {
    if (ip === "::" || ip === "::1") return true;
    const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isInternalAddress(mapped[1]);
    // fc00::/7 (unique local), fe80::/10 (link-local), ff00::/8 (multicast)
    return /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip) || /^ff/.test(ip);
  }
  return false;
}

/** Hostnames that name the local machine or a private network, whatever they resolve to. */
const INTERNAL_NAME = /(^localhost$)|(\.localhost$)|(\.local$)|(\.internal$)|(\.lan$)|(\.home\.arpa$)/;

/** Why `url` must not be called, or null. Checks the host as written, without resolving it. */
export function internalTargetProblem(url: string): string | null {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return "is not a valid URL";
  }
  if (INTERNAL_NAME.test(host)) return `host ${host} is a local or private name`;
  if (isInternalAddress(host)) return `host ${host} is an internal address`;
  return null;
}

/**
 * Throws unless every address `url` resolves to is public. Run just before a
 * request: a name that was fine when it was registered may point somewhere
 * else by now. (A name that changes between this check and the connection is
 * not caught; registering URIs is admin-only, which bounds that.)
 */
export async function assertPublicTarget(
  url: string,
  resolve: (host: string) => Promise<{ address: string }[]> = (host) => lookup(host, { all: true })
): Promise<void> {
  const problem = internalTargetProblem(url);
  if (problem) throw new Error(`refusing to call ${new URL(url).origin}: ${problem}`);
  const host = new URL(url).hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) return;
  const addresses = await resolve(host);
  const internal = addresses.find((entry) => isInternalAddress(entry.address));
  if (internal) throw new Error(`refusing to call ${host}: it resolves to the internal address ${internal.address}`);
}
