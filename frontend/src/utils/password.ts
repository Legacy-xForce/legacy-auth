// No look-alike characters (0/O, 1/l/I), so a password read aloud or retyped survives.
const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";

/** A random password from the browser's CSPRNG, without modulo bias. */
export function generatePassword(length = 16): string {
  const limit = 256 - (256 % CHARS.length);
  const out: string[] = [];
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) out.push(CHARS[byte % CHARS.length]);
    }
  }
  return out.join("");
}
