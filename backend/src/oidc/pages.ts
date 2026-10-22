import { createHash } from "crypto";

export const escapeHtml = (value: unknown) =>
  String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!);

// The console's look (OLED with a violet accent, Catppuccin Latte in light mode) without its
// fonts or scripts: the CSP allows inline styles only, and the theme the console stores in
// localStorage can't be read without a script, so the system color scheme picks the palette.
const STYLE = `
  :root{color-scheme:dark;--canvas:#000;--raised:#0e0d12;--line:#24232c;--fg:#f6f5fa;--muted:#a2a0af;--subtle:#74727f;
    --accent:#a78bfa;--primary:#a78bfa;--primary-hover:#c4b5fd;--on-primary:#140a2e;--success:#34d399;--danger:#fb7185;--chip:rgb(246 245 250/.06)}
  @media (prefers-color-scheme:light){:root{color-scheme:light;--canvas:#e6e9ef;--raised:#eff1f5;--line:#ccd0da;--fg:#4c4f69;--muted:#6c6f85;
    --subtle:#8c8fa1;--accent:#8839ef;--primary:#8839ef;--primary-hover:#7a2fd8;--on-primary:#fff;--success:#40a02b;--danger:#d20f39;--chip:rgb(76 79 105/.07)}}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;align-items:center;padding:0 1.25rem;
    font:15px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;color:var(--fg);
    background:radial-gradient(42rem 24rem at 50% -6rem,color-mix(in oklab,var(--accent) 15%,transparent),transparent 72%) no-repeat,var(--canvas)}
  main{width:100%;max-width:25rem;margin:clamp(3rem,16vh,9rem) 0 2.5rem;display:flex;flex-direction:column;align-items:center;text-align:center;
    animation:rise .5s cubic-bezier(.16,1,.3,1) both}
  .mark{display:grid;place-items:center;width:56px;height:56px;border-radius:16px;color:var(--fg);
    border:1px solid color-mix(in oklab,var(--accent) 25%,transparent);background:color-mix(in oklab,var(--accent) 10%,transparent);
    box-shadow:0 0 40px -6px color-mix(in oklab,var(--accent) 45%,transparent)}
  .mark svg{width:28px;height:28px}
  .mark .key{color:var(--accent)}
  .mark.ok{color:var(--success);border-color:color-mix(in oklab,var(--success) 25%,transparent);background:color-mix(in oklab,var(--success) 10%,transparent);
    box-shadow:0 0 40px -6px color-mix(in oklab,var(--success) 40%,transparent)}
  .mark.bad{color:var(--danger);border-color:color-mix(in oklab,var(--danger) 25%,transparent);background:color-mix(in oklab,var(--danger) 10%,transparent);
    box-shadow:0 0 40px -6px color-mix(in oklab,var(--danger) 35%,transparent)}
  h1{margin:1.25rem 0 0;font-size:1.625rem;line-height:2rem;font-weight:650;letter-spacing:-.02em}
  .lede{margin:.4rem 0 0;color:var(--muted)}
  h1,.lede{text-wrap:balance}
  noscript{align-self:stretch}
  .card{width:100%;margin-top:1.75rem;padding:1.5rem;border:1px solid var(--line);border-radius:20px;background:var(--raised);text-align:left}
  .card>:first-child,.card>form+button{margin-top:0}
  .desc+dl{margin-top:1rem}
  .card>dl:first-child{padding-top:0;border-top:0}
  form{margin:0}
  button,.btn{display:flex;align-items:center;justify-content:center;width:100%;height:48px;margin-top:.5rem;padding:0 1rem;border:0;border-radius:12px;
    font:inherit;font-weight:600;text-decoration:none;cursor:pointer;transition:background-color .15s,transform .1s}
  button:active,.btn:active{transform:scale(.98)}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  .primary{background:var(--primary);color:var(--on-primary)}
  .primary:hover{background:var(--primary-hover)}
  .ghost{background:transparent;color:var(--muted)}
  .ghost:hover{background:var(--chip);color:var(--fg)}
  .desc{margin:0;color:var(--fg)}
  dl{display:grid;grid-template-columns:auto 1fr;gap:.35rem .9rem;margin:0;padding-top:1rem;border-top:1px solid var(--line);
    font:12px/1.5 ui-monospace,"SF Mono","JetBrains Mono",Menlo,monospace}
  dt{color:var(--subtle)}
  dd{margin:0;color:var(--muted);overflow-wrap:anywhere}
  .spinner{width:22px;height:22px;margin:1.75rem auto 0;border:2.5px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
  footer{margin-top:auto;padding:0 0 1.5rem;font-size:12px;color:var(--subtle);text-align:center}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}}
  @keyframes spin{to{transform:rotate(1turn)}}
  @media (prefers-reduced-motion:reduce){main,.spinner{animation:none}}
`;

// The console's mark (a shield with a keyhole), and the two marks that replace the keyhole.
const SHIELD = `<path d="M12 2.75 4.75 5.6v5.55c0 4.55 3.05 8.4 7.25 10.1 4.2-1.7 7.25-5.55 7.25-10.1V5.6L12 2.75Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>`;
const MARKS = {
  brand:
    `<g class="key" fill="currentColor"><circle cx="12" cy="10.6" r="2"/>` +
    `<path d="M11.05 12.1h1.9l.45 3.55a.6.6 0 0 1-.6.68h-1.6a.6.6 0 0 1-.6-.68l.45-3.55Z"/></g>`,
  ok: `<path d="m9 12 2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`,
  bad: `<path d="M12 8.5v4M12 15.5h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>`,
};

const page = (title: string, mark: keyof typeof MARKS, body: string) =>
  `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">` +
  `<meta name="color-scheme" content="dark light"><meta name="referrer" content="no-referrer"><title>${escapeHtml(title)} · Legacy Auth</title>` +
  `<style>${STYLE}</style></head><body><main>` +
  `<div class="mark${mark === "brand" ? "" : ` ${mark}`}"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true">${SHIELD}${MARKS[mark]}</svg></div>` +
  `${body}</main><footer>One Legacy account for the calendar and the tracker.</footer></body></html>`;

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
      "brand",
      `<h1>Signing you out…</h1><p class="lede">This only takes a moment.</p>${withLogout}<div class="spinner" role="status" aria-label="Signing out"></div>` +
        `<noscript><style>.spinner{display:none}</style><div class="card"><p class="desc">JavaScript is off, so continue by hand:</p>` +
        `<button class="primary" type="submit" form="op.logoutForm">Sign out</button></div></noscript><script>${AUTO_SUBMIT}</script>`
    );
  }
  return page(
    "Sign out",
    "brand",
    `<h1>Sign out of Legacy?</h1><p class="lede">This signs you out of every Legacy app on this browser.</p>` +
      `<div class="card">${withLogout}<button class="primary" autofocus type="submit" form="op.logoutForm">Sign out of all apps</button>` +
      `<a class="btn ghost" href="${escapeHtml(options.origin)}/">Stay signed in</a></div>`
  );
}

export const signedOutPage = () => page("Signed out", "ok", `<h1>You're signed out</h1><p class="lede">You can close this window.</p>`);

/** A generic error page: only the OAuth error fields, never a stack trace or internal detail. */
export function errorPage(fields: Record<string, unknown>): string {
  const description = typeof fields.error_description === "string" && fields.error_description ? fields.error_description : null;
  const rows = Object.entries(fields)
    .filter(([key]) => ["error", "state"].includes(key))
    .map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join("");
  return page(
    "Something went wrong",
    "bad",
    `<h1>Something went wrong</h1><p class="lede">Go back to the app and try again.</p>` +
      (description || rows
        ? `<div class="card">${description ? `<p class="desc">${escapeHtml(/[.!?]$/.test(description) ? description : `${description}.`)}</p>` : ""}` +
          `${rows ? `<dl>${rows}</dl>` : ""}</div>`
        : "")
  );
}
