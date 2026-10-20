import { config } from "./config.ts";

// Several users can share one address (NAT, office), so an IP may fail more
// often than a single username before it is held back.
const IP_FAILURE_MULTIPLIER = 5;

type FailureWindow = { failures: number; startedAt: number };

const windows = new Map<string, FailureWindow>();

setInterval(() => {
  const now = Date.now();
  for (const [key, window] of windows.entries()) {
    if (now - window.startedAt >= windowMs()) {
      windows.delete(key);
    }
  }
}, 60_000).unref();

function windowMs() {
  return config.loginFailureWindowSeconds * 1000;
}

function limitFor(key: string) {
  return key.startsWith("ip:") ? config.loginMaxFailures * IP_FAILURE_MULTIPLIER : config.loginMaxFailures;
}

function activeWindow(key: string, now: number): FailureWindow | null {
  const window = windows.get(key);
  if (!window) return null;
  if (now - window.startedAt >= windowMs()) {
    windows.delete(key);
    return null;
  }
  return window;
}

/**
 * Whether an address is loopback or private. Seen on the socket, such an
 * address is a reverse proxy or Docker's port forwarder rather than the client,
 * so counting failures against it would make every client share one limit.
 */
export function isPrivateAddress(ip: string): boolean {
  const v4 = ip.startsWith("::ffff:") ? ip.slice("::ffff:".length) : ip;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(v4)) {
    const [a, b] = v4.split(".").map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  const lower = ip.toLowerCase();
  return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80:");
}

export function throttleKeys(ip: string | null, username?: string): string[] {
  const keys: string[] = [];
  if (username) keys.push(`user:${username.toLowerCase()}`);
  if (ip) keys.push(`ip:${ip}`);
  return keys;
}

/**
 * Seconds until the caller may try again, or `null` when none of `keys` has
 * used up its failures. Counted per fixed window from the first failure, so a
 * throttled caller is let back in once that window ends.
 */
export function retryAfterSeconds(keys: string[]): number | null {
  const now = Date.now();
  let retryAfterMs = 0;
  for (const key of keys) {
    const window = activeWindow(key, now);
    if (window && window.failures >= limitFor(key)) {
      retryAfterMs = Math.max(retryAfterMs, window.startedAt + windowMs() - now);
    }
  }
  return retryAfterMs > 0 ? Math.ceil(retryAfterMs / 1000) : null;
}

export function recordFailure(keys: string[]) {
  const now = Date.now();
  for (const key of keys) {
    const window = activeWindow(key, now);
    if (window) {
      window.failures += 1;
    } else {
      windows.set(key, { failures: 1, startedAt: now });
    }
  }
}

/** A successful sign-in clears its username's failures; the IP's stay counted. */
export function clearUserFailures(username: string) {
  windows.delete(`user:${username.toLowerCase()}`);
}
