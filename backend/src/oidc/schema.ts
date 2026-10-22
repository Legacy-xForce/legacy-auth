import type { SQL } from "bun";

/**
 * Tables of the OpenID Provider. Called from initDatabase(); every statement is
 * idempotent because there is no migration tool.
 */
export async function initOidcSchema(sql: InstanceType<typeof SQL>) {
  // Registered relying parties. Only hashes of secrets are stored.
  await sql`
    CREATE TABLE IF NOT EXISTS oidc_clients (
      client_id text PRIMARY KEY,
      client_secret_hash text,
      previous_secret_hash text,
      previous_secret_expires_at timestamptz,
      name text NOT NULL,
      redirect_uris text[] NOT NULL,
      post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
      backchannel_logout_uri text,
      allowed_scopes text[] NOT NULL,
      is_public boolean NOT NULL DEFAULT false,
      disabled_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `;

  // Added after the table first shipped; see clients.ts `primary_resource` / `default_resources`.
  await sql`ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS primary_resource text;`;
  await sql`ALTER TABLE oidc_clients ADD COLUMN IF NOT EXISTS default_resources text[] NOT NULL DEFAULT '{}';`;

  // Everything the provider library persists except sessions and clients:
  // grants, authorization codes, refresh tokens, interactions, replay guards.
  // `id` is a hash, never the bearer value, and `jti` is stripped from the
  // payload for the same reason (see adapter.ts).
  await sql`
    CREATE TABLE IF NOT EXISTS oidc_payloads (
      model text NOT NULL,
      id text NOT NULL,
      payload jsonb NOT NULL,
      grant_id text,
      user_code text,
      uid text,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      PRIMARY KEY (model, id)
    );
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_grant_id ON oidc_payloads(grant_id) WHERE grant_id IS NOT NULL;`;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_uid ON oidc_payloads(model, uid) WHERE uid IS NOT NULL;`;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_expires_at ON oidc_payloads(expires_at);`;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_payloads_account ON oidc_payloads((payload->>'accountId'));`;

  // Browser sessions at the OP. `id` is the session's stable uid (it survives
  // the identifier rotation done at login); `token_hash` is the hash of the
  // cookie value, which is what changes on rotation.
  await sql`
    CREATE TABLE IF NOT EXISTS oidc_sessions (
      id text PRIMARY KEY,
      token_hash text NOT NULL UNIQUE,
      user_id uuid REFERENCES users(id) ON DELETE CASCADE,
      auth_time timestamptz,
      amr text[],
      payload jsonb NOT NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz,
      ip text,
      user_agent text,
      created_at timestamptz NOT NULL DEFAULT now(),
      last_seen_at timestamptz NOT NULL DEFAULT now()
    );
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_sessions_user_id ON oidc_sessions(user_id);`;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires_at ON oidc_sessions(expires_at);`;

  // Back-channel logout deliveries that failed and are waiting to be retried.
  await sql`
    CREATE TABLE IF NOT EXISTS oidc_backchannel_retries (
      id bigserial PRIMARY KEY,
      client_id text NOT NULL,
      account_id text NOT NULL,
      sid text NOT NULL,
      attempts integer NOT NULL DEFAULT 1,
      next_attempt_at timestamptz NOT NULL,
      last_error text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `;
  await sql`CREATE INDEX IF NOT EXISTS idx_oidc_backchannel_retries_due ON oidc_backchannel_retries(next_attempt_at);`;
}
