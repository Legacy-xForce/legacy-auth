import { config } from "./config.ts";

/**
 * Digital Asset Links for passkeys in Android apps.
 *
 * Passkeys belong to this service's host. Android's passkey providers (Google
 * Password Manager and others) only let a native app use them once
 * /.well-known/assetlinks.json on that host names the app's package and
 * signing certificate. Each PASSKEY_ANDROID_APPS entry is
 * "<package>:<SHA-256 certificate fingerprint>".
 */

type AndroidApp = { packageName: string; fingerprint: string };

// Parsed at startup so a malformed entry fails loudly instead of silently
// breaking passkeys in the app.
const androidApps = config.passkeyAndroidApps.map(parseAndroidApp);

function parseAndroidApp(entry: string): AndroidApp {
  const separator = entry.indexOf(":");
  const packageName = entry.slice(0, separator).trim();
  const hex = entry.slice(separator + 1).replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (separator <= 0 || hex.length !== 64) {
    throw new Error(`PASSKEY_ANDROID_APPS: expected "<package>:<SHA-256 fingerprint>", got "${entry}"`);
  }
  return { packageName, fingerprint: hex.match(/../g)!.join(":") };
}

/** The assetlinks.json statements, or null when no app is configured. */
export function assetLinks() {
  if (androidApps.length === 0) {
    return null;
  }
  const byPackage = new Map<string, string[]>();
  for (const app of androidApps) {
    byPackage.set(app.packageName, [...(byPackage.get(app.packageName) ?? []), app.fingerprint]);
  }
  return [...byPackage].map(([packageName, fingerprints]) => ({
    relation: ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
    target: {
      namespace: "android_app",
      package_name: packageName,
      sha256_cert_fingerprints: fingerprints,
    },
  }));
}
