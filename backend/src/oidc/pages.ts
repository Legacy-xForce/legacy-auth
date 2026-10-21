import { createHash } from "crypto";

export const escapeHtml = (value: unknown) =>
  String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);

const STYLE = `
  :root{color-scheme:light dark}
  body{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:Canvas;color:CanvasText}
  main{width:min(24rem,calc(100% - 2rem));padding:1.5rem;border:1px solid color-mix(in srgb,CanvasText 20%,transparent);border-radius:.75rem}
  h1{font-size:1.15rem;margin:0 0 1rem}
  p{margin:.5rem 0}
  button{font:inherit;width:100%;padding:.6rem;margin-top:.5rem;border-radius:.5rem;border:1px solid color-mix(in srgb,CanvasText 30%,transparent);background:transparent;color:inherit;cursor:pointer}
  button.primary{background:CanvasText;color:Canvas}
  a{color:inherit}
  pre{white-space:pre-wrap;word-break:break-word;margin:.25rem 0}
`;

const page = (title: string, body: string) =>
  `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
  `<meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;

// The one inline script of the OP's own pages. The CSP names its hash, so it is
// the only script that may run.
const AUTO_SUBMIT = `document.getElementById("op.logoutForm").submit();`;
const AUTO_SUBMIT_HASH = `'sha256-${createHash("sha256").update(AUTO_SUBMIT).digest("base64")}'`;

export const LOGOUT_CSP = `default-src 'none'; style-src 'unsafe-inline'; script-src ${AUTO_SUBMIT_HASH}; frame-ancestors 'none'; base-uri 'none'`;
export const STATIC_PAGE_CSP = `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'`;

/**
 * The confirmation shown by RP-initiated logout. `form` is the library's own
 * form (it holds the XSRF token). Posting `logout=yes` ends the single sign-on
 * session and tells every app to drop its own; without it only the app that
 * asked would be signed out. When the app asked (it sent an id_token_hint) the
 * user has already chosen to sign out, so the form submits itself.
 */
export function logoutPage(form: string, options: { autoSubmit: boolean; origin: string }): string {
  const withLogout = form.replace("</form>", `<input type="hidden" name="logout" value="yes"/></form>`);
  if (options.autoSubmit) {
    return page(
      "Signing out",
      `<h1>Signing you out…</h1>${withLogout}<noscript><p>JavaScript is off, so continue by hand:</p>` +
        `<button class="primary" type="submit" form="op.logoutForm">Sign out</button></noscript><script>${AUTO_SUBMIT}</script>`
    );
  }
  return page(
    "Sign out",
    `<h1>Sign out of Legacy?</h1><p>This signs you out of every Legacy app on this browser.</p>${withLogout}` +
      `<button class="primary" autofocus type="submit" form="op.logoutForm">Sign out of all apps</button>` +
      `<p><a href="${escapeHtml(options.origin)}/">Stay signed in</a></p>`
  );
}

export const signedOutPage = () => page("Signed out", `<h1>You are signed out</h1><p>You can close this window.</p>`);

/** A generic error page: only the OAuth error fields, never a stack trace or internal detail. */
export function errorPage(fields: Record<string, unknown>): string {
  const rows = Object.entries(fields)
    .filter(([key]) => ["error", "error_description", "state"].includes(key))
    .map(([key, value]) => `<pre><strong>${escapeHtml(key)}</strong>: ${escapeHtml(value)}</pre>`)
    .join("");
  return page("Something went wrong", `<h1>Something went wrong</h1>${rows}<p>Go back to the app and try again.</p>`);
}
