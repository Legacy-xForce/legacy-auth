# Legacy Auth as the OpenID Provider for every Legacy app

Status: plan, 2026-10-22. Umbrella: [legacy-auth#4](https://github.com/Legacy-xForce/legacy-auth/issues/4). Folds in
[#7](https://github.com/Legacy-xForce/legacy-auth/issues/7) (account page) and
[#8](https://github.com/Legacy-xForce/legacy-auth/issues/8) (tracker prerequisites), and takes into account the
legacytracker plan (`docs/oidc-migration.md`, branch `oidc-migration`) and the calendar BFF work in progress
(branch `oidc-bff-session`).

Snapshot it was written against:

| Repo | Ref | Notes |
|---|---|---|
| legacy-auth | `main` `edba46e` | OP merged (#5), two-resource tests (#6). |
| legacytracker | `origin/main` `3669a0f` | Local `oidc-migration` (`f5c2c23` plan, `5f67f3f` server accepts OP tokens) is not pushed; web OIDC client in progress (uncommitted `src/web/src/api/oidc.ts`). |
| legacy-calendar | `origin/main` `c02297e` | Local `oidc-bff-session` (uncommitted): BFF session, back-channel endpoint, HS256 passkey module deleted. |

---

## 1. Where things stand

**Done (do not redo).** Phase 0 hardening in all three repos; the OP itself (`backend/src/oidc`, `node-oidc-provider`
9.12.2 in-process on Bun): discovery, `/authorize`, `/token`, `/userinfo`, `/logout`, Authorization Code + PKCE S256
only, client registry and admin API, `__Host-legacy_session` with idle/absolute timeouts, RFC 9068 access tokens
per resource (RFC 8707), ID tokens with `acr`/`amr`, RP-initiated and back-channel logout with a retry queue,
refresh rotation with grant revocation on reuse, throttling, audit events, `OIDC_ENABLED=false` rollback.
Clients `calendar-web`, `tracker-web`, `tracker-mobile`, `auth-console` are seeded **disabled**.

**Open.** #8 (tracker prerequisites), #7 (account page + locking account endpoints), the rest of #4 (console off
`localStorage`, conformance suite, ROPC retirement, freshness decision), tracker #36 (device tokens minted from a
stolen session), PRs legacytracker#56 and legacy-calendar#12 (send `audience`).

**Found while reading the code for this plan (not in any issue yet).** Each was read, not run; check before fixing.

1. **Discovery advertises an endpoint that does not answer.** `pushedAuthorizationRequests` is on by default in
   oidc-provider 9.12.2, so discovery lists `pushed_authorization_request_endpoint` (`/request`), but
   `oidc/proxy.ts` only forwards `/authorize`, `/token`, `/userinfo`, `/logout`, discovery and `/interaction/*`.
   `dPoP` is also on by default and advertised, yet no resource server checks `cnf`. Both should be explicit
   decisions, not defaults (see D9).
2. **Requiring `nonce` everywhere will fail certification.** `strictAuthorizationRequests` refuses a code-flow
   request without `nonce`; the OpenID Foundation Basic OP plan has a test that such a request must succeed.
3. **No token revocation (RFC 7009) or introspection (RFC 7662).** Both are off. A native app cannot revoke its
   refresh token on sign-out, and resource servers have no way to check a token live.
4. **`calendar` and `tracker` are hard-coded** in `types.ts` (`APP_AUDIENCES`, `UserScopes`), `scopes.ts`,
   `defaultClients()`, the users' `scopes` JSON column, `resolveAudience`, and the console's two toggles. Every new
   project is a code change in at least six places.
5. **Public clients cannot have a back-channel URI** (`validateClientFields` refuses it), which #8 item 8 needs.
6. **The console has the same all-or-nothing consent problem as the tracker.** `consent()` refuses the whole
   sign-in when `admin` is requested by a non-admin, so a console that asks for `admin` cannot also serve the
   account page to ordinary users (#7).
7. **Two looks.** The logout, signed-out and error pages are server-rendered strings in `oidc/pages.ts`; the
   sign-in page is the Vue app. Users will see both during every sign-in and sign-out.
8. **Refresh-token lifetime is a hard 30 days for every client.** `ttl.Grant` equals `ttl.RefreshToken`, so a grant
   expires 30 days after sign-in regardless of rotation, and `expiresWithSession` also ties every refresh token
   to the 14/30-day browser session. Exempting native clients (#8 item 9) means changing both.
9. **The `profile` scope carries a non-standard `role` and lacks standard claims** (`picture`, `updated_at`).
   The apps already build profile-picture URLs by hand.

---

## 2. Target

One sign-in page, one session, one account page, one admin console, all at `https://auth.legacy-group.tech`.
Every app, today's and tomorrow's, is a registered client of a standards-compliant OP and never sees a password or
runs its own passkey ceremony.

```
                       auth.legacy-group.tech  (issuer, passkey RP ID - unchanged forever)
   ┌──────────────────────────────────────────────────────────────────────────────────┐
   │  OP (oidc-provider)          Sign-in surface      Account surface   Admin surface │
   │  /authorize /token /userinfo /interaction/:uid    /account          /admin        │
   │  /logout /revoke /introspect (Vue, own entry)     (Vue, console BFF session)      │
   │  /.well-known/*                                                                   │
   └──────────────────────────────────────────────────────────────────────────────────┘
        ▲ code+PKCE        ▲ code+PKCE           ▲ code+PKCE          ▲ client_credentials
  calendar-web (BFF,  tracker-spa (public,   tracker-mobile        future services /
  confidential)       browser, any domain)   (public, native)      bots (machine)
        │                    │  └──── second token, aud=calendar ────► calendar API
        ▼                    ▼
   calendar API         tracker API      ◄── back-channel logout + security events (SET)
```

### Client archetypes (what a new project picks)

| Archetype | Example | Client type | Grant(s) | Tokens live | Logout |
|---|---|---|---|---|---|
| Web app with its own server | calendar, console | confidential, `client_secret_basic` | code + PKCE, refresh | server session (BFF), `httpOnly` cookie | RP-initiated + back-channel |
| Static SPA on several domains | tracker web | public, `none` | code + PKCE, refresh (rotating) | access in memory, refresh in `localStorage` (risk accepted per app) | RP-initiated; back-channel to the app's API server |
| Native app | tracker mobile | public, `none`, custom scheme or claimed https | code + PKCE via system browser (AppAuth), refresh | Keychain / EncryptedSharedPreferences | revoke refresh (RFC 7009) + RP-initiated |
| Service / bot (no user) | future | confidential | `client_credentials` | memory | n/a |
| Device without a browser (CLI, bot linking) | future, only if needed | public | device authorization (RFC 8628) | device | revoke |

### Standards, where each stands

| Spec | Today | Action |
|---|---|---|
| OIDC Core 1.0 (code flow) | done | relax `nonce` (D8); add `picture`, `updated_at`; move `role` to its own scope (D10) |
| OIDC Discovery 1.0 | done, but advertises PAR and DPoP (finding 1) | discovery must list only what works; test it |
| RP-Initiated Logout 1.0 | done | restyle pages (Phase 4) |
| Back-Channel Logout 1.0 | done, confidential clients only | allow for public clients (#8.8) |
| RFC 6749 / OAuth 2.1 draft | code + refresh; ROPC still at `/auth/login` | retire ROPC (Phase 5) |
| RFC 7636 PKCE | S256 required | keep |
| RFC 9700 Security BCP | exact redirect matching, rotation, reuse detection | refused refresh must not spend the token (#8 comment) |
| RFC 8707 Resource Indicators | done | per-client default and required resources (#8.3, #8.4) |
| RFC 9068 JWT access tokens | done, plus legacy `type`/`scopes` | resource servers check `scope`; then drop legacy claims (Phase 5) |
| RFC 9207 `iss` in authorization response | on (library advertises `authorization_response_iss_parameter_supported`) | clients must check it (`oauth4webapi` / `openid-client` do) |
| RFC 7009 Revocation | off | enable (Phase 2) |
| RFC 7662 Introspection | off | enable for resource servers only (Phase 2, D5) |
| RFC 8417 Security Event Tokens | none | access-revoked / account-disabled push to resource servers (D6) |
| RFC 9126 PAR | on by accident, unreachable | off now; turn on deliberately later |
| RFC 9449 DPoP | on by accident, unchecked | off now; mobile later (Phase 6) |
| OIDF conformance | not run | Basic OP, Config OP, RP-Initiated Logout OP, Back-Channel Logout OP |

---

## 3. Decisions

| # | Decision | Recommendation | State |
|---|---|---|---|
| D1 | OP implementation | Keep `oidc-provider` in-process on Bun, pinned, with the two patches pinned by tests. Add a CI job that runs the OP suite under Node too, so a Bun regression is caught and the Node-sidecar fallback stays one config change away. | decided (#5), CI job new |
| D2 | Web app token storage | Per app. BFF where the app has a server on the same site (calendar, console). Public SPA where the app must run on many domains (tracker web, risk accepted on #4). New apps default to BFF. | decided |
| D3 | Apps and resources are data, not code | `oidc_resources` + `user_resource_access` tables, admin API and UI (Phase 3). Adding a project = register a resource, a client, grant users access. No deploy of Legacy Auth. Done **now**, right after Phase 1, not after the two apps have migrated. | decided 2026-10-22 |
| D4 | Per-app admin | The global `role` only means "admin of Legacy Auth". App admin rights become app scopes (`calendar.admin`), granted like any other. Calendar keeps reading `role` until it switches. | decided 2026-10-22 |
| D5 | Freshness of permissions | Up to 15 minutes of access after revocation is acceptable. Keep 15 min access tokens; entitlement re-checked on every refresh (done); security events push revocation and disabling to resource servers (D6); introspection for an endpoint that must be instant. No `token_version`. | decided 2026-10-22 (#4 open question 3) |
| D6 | Telling resource servers about lost access | RFC 8417 Security Event Tokens POSTed to a per-resource `events_uri`, signed with the OP key, with the back-channel retry queue. Events: RISC `account-disabled`, `account-purged`, and `urn:legacy:secevent:access-revoked` (`resource`, `scopes`). A logout token cannot say *why* a session ended, so the tracker's API-token purge (its plan 1.3) listens here, not on back-channel logout. | **proposed** |
| D7 | Native refresh tokens | Not tied to the browser session (`expiresWithSession` false for `application_type: native`). Idle 30 days, absolute 180 days, by giving native grants their own `ttl.Grant`/`ttl.RefreshToken`. Ended by app sign-out (revocation), access loss, disabling, or password change. | decided 2026-10-22 (#8.9) |
| D8 | `nonce` | Required only for public clients (where it adds something next to PKCE); optional for confidential ones, as OIDC Core says. Needed to pass certification. | **proposed** |
| D9 | PAR, DPoP | Explicitly off now. PAR can be required later for confidential clients; DPoP for the mobile app in Phase 6. | **proposed** |
| D10 | Claims | `profile` = `preferred_username`, `picture` (the existing profile-picture URL), `updated_at`. New scope `roles` carries `role`. Access tokens keep `username`/`role` as extra claims. | **proposed** |
| D11 | Console auth | The console becomes an RP of its own OP (`auth-console`, confidential, BFF inside the Bun server). Account and admin endpoints accept only that session; other apps' tokens get 401 there (#7.5). | decided (#4 §2.4, #7) |
| D12 | Signing keys | Support a key set: active, next (published ahead), retired (published until its tokens expire). The current key stays active; rotation becomes a runbook, not an outage. Passkeys are unaffected: they depend on the RP ID, not this key. | **proposed** |
| D13 | Issuer and RP ID | Stay `https://auth.legacy-group.tech` forever (#4 open question 6). | decided 2026-10-22 |
| D14 | Language | English only. No i18n layer. | decided 2026-10-22 |
| D15 | Account recovery | There are no email addresses and none will be collected. Recovery stays with admins, on the user's request: an admin issues a single-use setup link (Phase 4.4) or, as a fallback, a temporary password the user must replace at the next sign-in. Users manage their own password and passkeys on the account page. | decided 2026-10-22 (#4 open question 4) |

---

## 4. Work plan: legacy-auth

Sizes are rough: S under a day, M a few days, L a week or more.

### Phase 1 — Unblock the tracker (#8). Ship first.

The tracker's server work (its Phase 1) can proceed now; its web and mobile phases wait on this.

- [ ] **Refused refresh must not spend the token** (#8 comment). Before the library sees a `refresh_token` grant,
  resolve the presented token (hash lookup in `oidc_payloads`), and when it is valid for the authenticated client
  but names a `resource` the grant lacks, or one the user is no longer entitled to, answer `invalid_target`
  without forwarding. Do it in `proxy.ts` (it already reads `/token` requests) after client authentication would
  succeed, so it never reveals anything about a token to the wrong client. Flip the three pinned tests in
  `oidc-two-resources.test.ts`. M
- [ ] **Optional secondary resources and scopes at consent** (#8.3, and finding 6 for `admin`). Client columns
  `required_resources text[]` and the rule: refuse with `access_denied` only when the user lacks a required
  resource; silently drop unentitled scopes of the others (and `admin` for non-admins). The grant then holds only
  what the user has. M
- [ ] **Default resources per client** (#8.4): `default_resources text[]`, used by `defaultResource` when the
  request names none. S
- [ ] **`tracker-spa` client** (#8.1): public, redirect and post-logout URIs per domain
  (`tracker.legacy-group.tech`, `legacytracker.pages.dev`; `http://localhost:5173` only in dev), scopes
  `openid profile offline_access tracker.read tracker.write calendar.read`, `required_resources
  [urn:legacy:tracker]`, `default_resources [urn:legacy:tracker, urn:legacy:calendar]`. Drop `tracker-web` from
  `defaultClients()`. `tracker-mobile`: add `calendar.read`, `com.legacy.legacytracker:/logout`, same resource
  settings. S
- [ ] **Back-channel URIs for public clients** (#8.8): lift the refusal in `validateClientFields`; the URI is the
  app's server, https only, net-safety checks unchanged. Send logout tokens on account disable/delete, password
  change (already) and on removal of that app's access. S
- [ ] **CORS on `/token` and discovery for public clients** (#8.2): an end-to-end test through the Bun proxy:
  preflight, one `Access-Control-Allow-Origin`, nothing duplicated by `cors.ts`. S
- [ ] **Native refresh lifetime** (#8.9, D7): for `application_type: native`, `expiresWithSession` false, refresh
  idle 30 days, grant absolute 180 days, through per-client `ttl.Grant` and `ttl.RefreshToken`. Browser clients
  keep 14/30 days tied to the session. Document both in the README. S
- [ ] **Enable revocation** (RFC 7009) now rather than in Phase 2, because the mobile sign-out needs it. Route
  `/revoke` through the proxy. S

Acceptance: the four scenarios of #8 item 6 pass, plus: a tracker-only user signs in to the tracker with the
default resources and keeps the session after a refused calendar refresh; a public client receives a logout token.

### Phase 2 — Spec hygiene and certification

- [ ] Disable PAR and DPoP explicitly (D9); a discovery test asserts every advertised endpoint answers and every
  advertised feature is on purpose. S
- [ ] `nonce` per D8. S
- [ ] Introspection (RFC 7662) for resource servers only: authenticated with a resource-server credential (a
  confidential client with no redirect URIs and only the `introspection` grant), `active` false for revoked
  grants, ended sessions, disabled users. M
- [ ] Claims per D10; `picture` URL built from the issuer. S
- [ ] Key set and rotation runbook (D12): `JWT_PRIVATE_KEYS` (or the next key in Postgres, encrypted), JWKS
  publishes all non-expired keys, tokens signed with the active `kid`. Check that both resource servers refetch
  the JWKS on an unknown `kid` (tracker uses `jose` `createRemoteJWKSet`, which does; check the calendar's). M
- [ ] Security events (D6): `events_uri` on resources, SET signing (`typ: secevent+jwt`), delivery through the
  generalised retry queue (`oidc_backchannel_retries` → `oidc_deliveries` with a `kind`). M
- [ ] `client_credentials` grant (off until the first service needs it, but designed now): resource-scoped tokens
  with `sub` = client, no `username`/`role`. S
- [ ] **Conformance**: deploy a staging OP reachable from the internet (separate issuer, separate DB), register a
  conformance client, run Basic OP, Config OP, RP-Initiated Logout OP, Back-Channel Logout OP. Fix and record the
  results in the README. M
- [ ] OpenAPI: document the OP endpoints, account and admin APIs in `openapi.ts` (#4 §1.3). S

### Phase 3 — Many apps: resources, access, consent

Starts right after Phase 1 (D3). Phase 1's `required_resources` and `default_resources` columns are part of this
schema, so build them in their final shape there.

Schema (idempotent, in `initOidcSchema`):

```sql
CREATE TABLE IF NOT EXISTS oidc_resources (
  indicator         text PRIMARY KEY,               -- urn:legacy:calendar
  audience          text NOT NULL UNIQUE,           -- calendar (the token's aud)
  name              text NOT NULL,
  scopes            text[] NOT NULL,                -- calendar.read, calendar.write, calendar.admin
  scope_labels      jsonb NOT NULL DEFAULT '{}',    -- shown on consent and in the console
  access_token_ttl  integer,                        -- NULL = ACCESS_TOKEN_TTL_SECONDS
  events_uri        text,                           -- security events (D6)
  disabled_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS user_resource_access (
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  indicator   text NOT NULL REFERENCES oidc_resources(indicator) ON DELETE CASCADE,
  scopes      text[] NOT NULL,
  granted_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, indicator)
);
ALTER TABLE oidc_clients
  ADD COLUMN IF NOT EXISTS application_type   text NOT NULL DEFAULT 'web',   -- web | native | service
  ADD COLUMN IF NOT EXISTS first_party        boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS client_uri         text,
  ADD COLUMN IF NOT EXISTS logo_uri           text,
  ADD COLUMN IF NOT EXISTS required_resources text[] NOT NULL DEFAULT '{}',  -- Phase 1
  ADD COLUMN IF NOT EXISTS default_resources  text[] NOT NULL DEFAULT '{}';  -- Phase 1
```

- [ ] Seed `urn:legacy:calendar` and `urn:legacy:tracker`; backfill `user_resource_access` from `users.scopes`
  (`true` → read and write). Run the backfill on every boot until the column is dropped, so the legacy admin API
  and the new one cannot drift. M
- [ ] Replace `APP_AUDIENCES`, `RESOURCE_SERVERS`, `entitledResourceScopes`, `resolveAudience` with lookups
  (cached, invalidated on admin writes). The legacy `scopes` claim and `/auth/login`'s `audience` are computed
  from the table for `calendar` and `tracker` only. M
- [ ] `application_type` stored instead of inferred from custom schemes. S
- [ ] Admin API: `GET/POST/PATCH /admin/oidc/resources`, `PUT/DELETE /admin/users/:id/access/:indicator`; the old
  `scopes` body on `PATCH /admin/users/:id` keeps working. Revoking access ends that app's grants and sends a
  logout token and a security event. M
- [ ] **Consent screen for third-party clients** (`first_party = false`): the OP shows what the app asks for,
  remembers the grant, and the account page lists it with a revoke button. First-party clients stay automatic. M
- [ ] Integration guide `docs/integrating.md`: pick an archetype, register, env template, verifying tokens
  (`iss`, `aud`, `typ: at+jwt`, `exp`, `scope` per method), back-channel and security-event endpoints, local
  development against a throwaway OP. Reference snippets for `openid-client` (BFF), `oauth4webapi` (SPA),
  `flutter_appauth` (mobile), `jose` (resource server). S

### Phase 4 — Frontend redesign

Today: one Vue SPA with an ROPC `/login` form, the OP sign-in page (`/interaction/:uid`), and a console with users
(two hard-coded app toggles) and personal settings; tokens in `localStorage`; dark only; the OP's other pages are
unstyled server strings. The OP needs three surfaces that share one design system.

#### 4.1 Foundations

- [ ] **Two Vite entries.** `signin` (the interaction pages: tiny bundle, strict CSP `script-src 'self'`, never
  loads console code) and `app` (account + admin). Same repo, same components.
- [ ] **Design system.** Keep Vue 3, Vite, Tailwind 4 tokens (`style.css` `@theme`), Pinia, vue-router, Iconify.
  Add `reka-ui` for accessible primitives (dialog, menu, tabs, tooltip, toast, combobox) instead of growing
  `ConfirmDialog.vue`. Components: Button, Field/Input, PasswordInput, Select, Switch, Badge/StatusPill, Card,
  Table (sortable, paginated, empty and loading states), Tabs, Dialog, Toast, CopyField, SecretReveal (shown
  once), UriListEditor (validates like `redirectUriProblem`), ScopePicker (grouped by resource), Avatar.
- [ ] **Light and dark themes** from `prefers-color-scheme`, with a toggle; WCAG AA contrast; keyboard and focus
  handling; `prefers-reduced-motion`.
- [ ] **English only** (D14): plain strings in the components, no i18n library.
- [ ] **Mobile first.** The sign-in and account pages run inside Custom Tabs and `ASWebAuthenticationSession`;
  design at 360 px first.
- [ ] **Typed API.** Generate frontend types from `openapi.ts` (`openapi-typescript`), as the calendar does.
- [ ] **One styled shell for server pages.** `pages.ts` keeps rendering logout, signed-out and error pages without
  JavaScript (they must work when the bundle is broken), but with the same tokens via a small shared stylesheet
  built from `style.css`.
- [ ] **Tests**: Vitest + `@vue/test-utils` for components; Playwright end to end against a local OP with a
  throwaway Postgres, using Chromium's virtual authenticator for passkeys. The frontend has no tests today.

#### 4.2 Sign-in surface (`/interaction/:uid`, public)

| State | What the user sees |
|---|---|
| Identify | "Sign in to **Legacy Tracker**" (client name and `logo_uri`), username with `autocomplete="username webauthn"` and conditional passkey autofill, "Use a passkey" button |
| Password | password field, "Back" to change user, throttled state with a `Retry-After` countdown |
| Continue as | when a session exists but the client sent `prompt=login` or `max_age`: "Continue as alice" or "Use another account" |
| Set new password | after signing in with a temporary password an admin set (D15): choose a new one (and optionally add a passkey) before continuing to the app |
| Setup link | `/setup/:token` from an admin (D15): set a password and/or register a passkey, then continue to the account page. Single use, expires after 24 h, stored as a hash. |
| Forgot password | a line of text, no form: "Ask an admin to reset your access." |
| No access | the user signed in but cannot use this app: "Your account can't use Legacy Tracker", **Back to Legacy Tracker** (ends with `error=access_denied` at the client), **Use another account**. Replaces each app's own "access restricted" screen. |
| Consent | third-party clients only (Phase 3): app, scopes in words, Allow / Deny |
| Expired | "This sign-in link has expired", back to the app |

The backend already has `/interaction/:uid/details`, `login`, `passkey/options`, `passkey/verify`, `abort`; add
`details.client.logo_uri`, a `no_access` prompt and `continue`/`switch` actions.

#### 4.3 Account surface (`/account`, any signed-in user; the #7 deep link)

- **Overview**: profile card, the apps the user can open (from access + `client_uri`).
- **Profile**: picture, username.
- **Security**: change password; passkeys (name, created, last used, rename, remove, add).
- **Sessions**: browser sessions from `oidc_sessions` (device, address, last seen, "this browser"); sign out one or
  all others (ends their refresh tokens and sends back-channel logouts).
- **Connected apps**: grants per client with scopes and last use; revoke.
- **Activity**: the user's own `auth_events`.
- `?return_to=` shows "Back to <app>"; accepted only for origins of a registered redirect or post-logout URI, or a
  registered native scheme (#7.3).

Backend: `/account/*` JSON API authenticated by the console session (4.5); the self-service parts of `/auth/me`,
`/auth/change-password`, `/auth/passkey/*`, `/auth/profile-picture` move there. The old routes keep working for
ROPC clients until Phase 5, but reject OP tokens whose `aud` is another app (#7.5). Rename and last-used passkey
fields need two columns on `passkey_credentials`.

#### 4.4 Admin surface (`/admin`, role `admin`)

- **Users**: searchable, filterable (status, role, app) table. Detail tabs: Overview, **Access** (a row per
  registered resource, a switch per scope, so a new app appears without frontend work), Security, Activity,
  Danger zone (disable, delete).
- **Recovery, on a user's request** (D15), in the user's Security tab:
  - **Create a setup link** (preferred): single use, 24 h, shown once with a copy button for the admin to send by
    chat. The admin never learns the password. New users get one instead of an initial password.
  - **Set a temporary password**: sets `must_change_password`; the sign-in surface makes the user replace it.
  - Remove passkeys, sign out all sessions (ends every app's grant and sends back-channel logouts).
  - Each action is audited (`admin_user_setup_link`, `admin_user_password_reset`, …) and the user sees it under
    Activity on the account page.
  - Backend: `user_setup_tokens` (hash, user, created_by, expires_at, used_at) and `users.must_change_password`;
    `POST /admin/users/:id/setup-link`; the interaction handler checks the flag after a password sign-in.
- **Applications** (clients): list with archetype badges. Create through a short wizard by archetype (2.1), which
  presets public/confidential, auth method and grant types and validates URIs as the server does. Detail: URIs,
  scopes by resource, required/default resources, back-channel URI, first-party flag, secret rotation (one-time
  reveal, grace period), enable/disable, an integration panel (issuer, discovery URL, `client_id`, env template).
  This replaces "use the admin API" from #4 §1.2: with more apps coming, curl is the error-prone path.
- **APIs** (resources): indicator, audience, scopes with labels, token TTL, events URI.
- **Audit log**: the existing `GET /admin/audit-events` with filters and a detail drawer.
- **System**: discovery and JWKS links, signing keys (active, next, retired), OP status, session and token
  lifetimes (read-only), last conformance run.

#### 4.5 Console signs in through the OP (D11, #4 §2.4, #7.1)

- [ ] BFF inside the Bun server with `openid-client`: `GET /console/login` → `/authorize` (client `auth-console`,
  `scope=openid profile roles offline_access admin`, `admin` optional per Phase 1), `GET /auth/callback`,
  `POST /auth/backchannel-logout`, `POST /console/logout` → `/logout`. These are the URIs already seeded. M
- [ ] `console_sessions` table (cookie hash, user, `sid`, encrypted tokens, expiries); cookie
  `__Host-legacy_console`, `HttpOnly; Secure; SameSite=Lax; Path=/`; refresh server-side with a per-session lock;
  CSRF by `Origin` and `Sec-Fetch-Site` on every state-changing route. M
- [ ] Delete `stores/auth.ts`'s `localStorage` handling and the ROPC `/login` view; the router guard asks the BFF
  `GET /console/session`. S

### Phase 5 — Retire the legacy paths

Only after the calendar BFF, tracker web and a tracker app release with minimum-version enforcement have shipped.

- [ ] Resource servers check RFC 9068 `scope` per method (tracker plan 1.1 does; the calendar still reads
  `scopes.calendar`), then stop reading `type`/`scopes`.
- [ ] `REQUIRE_AUDIENCE=true`, then remove `/auth/login`, `/auth/refresh`, `/auth/logout`, the passkey login
  endpoints and `refresh_tokens`, after a release cycle with no traffic (watch `auth_events`).
- [ ] Drop `type`, `scopes`, `username`, `role` from access tokens (keep `username` if an app still needs it
  without `/userinfo`); drop `users.scopes`.
- [ ] Set `OIDC_COOKIE_KEYS` explicitly before `JWT_SECRET` can go (the cookie keys are derived from it today).

### Phase 6 — Later, on demand

- Step-up for admin actions: `max_age` re-authentication, then TOTP or a second passkey enforced through
  `acr`/`amr`.
- DPoP for the mobile app's refresh tokens.
- Federation (Google, Apple) at the OP. With no email addresses (D15), an external identity is linked only by
  the signed-in user from the account page, or by an admin, never automatically.
- Device authorization grant, if a CLI or bot needs a user's token.
- Token exchange (RFC 8693), only if one server must call another on a user's behalf.

---

## 5. Work in the apps

### legacy-calendar (BFF, `calendar-web`)

The `oidc-bff-session` work matches this plan. Remaining items:

- [ ] Merge PR #12 (`audience: "calendar"`) now: nothing found sends the calendar's token to another app, so it
  closes the replay window until the BFF ships.
- [ ] Check `scope` (`calendar.read` for reads, `calendar.write` otherwise) on OP tokens, not just `scopes`.
- [ ] Accept calendar tokens issued to `tracker-spa` and `tracker-mobile` (`client_id` allow-list), test it, and
  allow the tracker web origins in CORS for the routes the tracker calls.
- [ ] "Manage account" links to `/account?return_to=…`; nothing else of passkey or password management stays.
- [ ] Optional: an `events_uri` for access revocation (D6), to drop its own sessions and API tokens at once.
- Needs from legacy-auth: `calendar-web` secret and enable (ops); Phase 4.3 before its passkey UI goes.

### legacytracker (public `tracker-spa`, native `tracker-mobile`)

Follows `docs/oidc-migration.md`. Changes this plan makes to it:

- Plan 1.3: purge API tokens on a security event (D6) at a new `events_uri`, not on a logout token, which cannot
  carry a reason.
- Plan 2.4 and 3.2: after Phase 1's "refused refresh does not spend the token", the `scopes.calendar` pre-check
  can go; until then keep it.
- Plan 3.2: on sign-out, revoke the refresh token at `/revoke` before `end_session`.
- Plan 1.2: device registration requires `client_id = tracker-mobile` (#36), as written.
- Close PR #56 when the web phase ships.
- Needs from legacy-auth: Phase 1 for web and mobile; Phase 4.3 before the app deletes its passkey screen.

### A new project

1. Pick an archetype (section 2). 2. In the console: register its API under **APIs** and its client under
**Applications**. 3. Grant users access under **Users → Access**. 4. Follow `docs/integrating.md`. No change to
Legacy Auth's code.

---

## 6. Order and dependencies

```
legacy-auth P1 (#8) ──┬──► tracker web (plan P2) ──┐
                      └──► tracker app + min version (plan P3) ──┐
legacy-auth P4.1-4.3 ─────► both apps drop their passkey screens  │
calendar BFF (in progress) ───────────────────────────────────────┤
legacy-auth P4.5 (console via OP) ────────────────────────────────┼──► legacy-auth P5 (retire ROPC)
legacy-auth P2 (hygiene, conformance) ── any time after P1        │
legacy-auth P3 (data-driven apps) ── right after P1 (D3) ─────────┘
```

Sequence for legacy-auth: P1 → P3 (D3: now) → P4.1 + P4.2 (the sign-in page becomes every user's first
impression when the apps cut over, so restyle it before that) → P4.5 + P4.3 (closes #7) → P4.4 → P2 → P5.
P2's small items (PAR/DPoP off, `nonce`) can ride along with P1.

Each step is independently deployable and reversible: `OIDC_ENABLED=false` for the OP, per-client
`disable`, the apps' own flags (`VITE_AUTH_MODE=legacy` in the tracker), and ROPC stays alive until P5.

---

## 7. Testing

- Keep the existing pattern: real OP over HTTP, browser emulator, software authenticator, throwaway Postgres.
- New suites: refused-refresh does not rotate; required vs optional resources; default resources; public-client
  back-channel; revocation; introspection; security events (signature, retries); discovery advertises only working
  endpoints; resource and access admin API; console BFF (CSRF, fixation, back-channel ends the console session,
  other apps' tokens get 401 at `/account/*`).
- Frontend: Vitest for components; Playwright for sign-in (password, passkey, no-access, continue-as), account
  (passkey add/remove, sessions, return links), admin (create each client archetype, rotate secret, grant access).
- Conformance: the four OIDF plans against staging, before Phase 5.
- Cross-repo smoke on staging: calendar BFF, tracker web and an emulator build against the same OP: SSO both
  ways, sign-out propagation, calendar events on the tracker map for a user with and without calendar access.

---

## 8. Decisions taken (2026-10-22)

1. **D5:** up to 15 minutes of access after revocation is acceptable; event push and introspection where it matters.
2. **D7:** native refresh tokens are independent of the browser session, 30 days idle / 180 days absolute.
3. **D13:** `auth.legacy-group.tech` stays the issuer and passkey RP ID permanently.
4. **D3/D4:** data-driven apps and per-app admin scopes now (Phase 3 right after Phase 1).
5. **D14:** English only.
6. **D15:** no email. Admins handle recovery on request (setup links, temporary passwords); nothing blocks retiring
   ROPC on this.

Still open: D2 for future apps is a default, not a rule; D6, D8, D9, D10, D11, D12 are recommendations nobody has
objected to. Treat them as decided unless someone does.

---

## 9. Open items

Not decided or not yet verified. None blocks starting Phase 1.

### Missing from the phases above

- [ ] **Production CORS.** Set `CORS_ALLOWED_ORIGINS` on all three services (#4 Phase 0 leftover). The manifests live on
  the VPS in `~/legacy`, not in a repo, so this is an ops task for whoever has SSH.
- [ ] **Backups before production schema changes.** Phase 3 adds tables and backfills `user_resource_access` from
  `users.scopes`; Phase 5 drops `users.scopes` and `refresh_tokens`. Each needs a `pg_dump` first (see `CLAUDE.md`),
  the exact statements stated and confirmed, and a rollback. There are no automated backups yet: decide whether to
  add them before Phase 3.
- [ ] **Staging OP for conformance (Phase 2).** Needs its own issuer (subdomain), its own database, internet
  reachability and a place in the compose project on the VPS. Not specified yet.
- [ ] **`/settings` redirect.** #7 and the tracker plan link to `/settings`; this plan names the page `/account`.
  `/settings` must redirect to `/account` and keep `?return_to=`.
- [ ] **Calendar guest invite links** must keep working without a session when the calendar moves to the BFF
  (#4 §2.2). Add a test on the calendar side.
- [ ] **Follow-ups outside this repo.** Update legacytracker `docs/oidc-migration.md` with the changes in section 5
  (security events instead of logout tokens for the API-token purge, revoke before `end_session`); comment on #4
  linking this plan; open one issue per phase.

### Findings from reading the code, not yet reproduced

Confirm each against a local OP with a throwaway Postgres (never production) before building on it.

1. Discovery lists `pushed_authorization_request_endpoint` (`/request`), which `oidc/proxy.ts` does not forward.
2. `strictAuthorizationRequests` requires `nonce`, which the OIDF Basic OP plan expects to be optional.
3. The grant lifetime (`ttl.Grant` = `ttl.RefreshToken` = 30 days) caps refresh tokens regardless of rotation.
4. `consent()` refuses the whole sign-in when a non-admin requests `admin`.
5. A refused refresh spends the refresh token (already pinned by `oidc-two-resources.test.ts`).
