export type UserRole = "admin" | "user";

export type UserScopes = {
  calendar: boolean;
  tracker: boolean;
};

// Apps that accept this service's access tokens. Each is both a key of
// `UserScopes` and an `aud` value, so a token only names apps the user may use.
export const APP_AUDIENCES = ["calendar", "tracker"] as const;

export type AppAudience = (typeof APP_AUDIENCES)[number];

export type UserRecord = {
  id: string;
  username: string;
  password_hash: string;
  role: UserRole;
  active: boolean;
  scopes: UserScopes;
  created_at: string;
  updated_at: string;
};

export type RefreshTokenRecord = {
  id: string;
  user_id: string;
  jti: string;
  token_hash: string;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
};

export type PasskeyCredentialRecord = {
  id: string;
  user_id: string;
  public_key: string;
  counter: string | number;
  device_name: string | null;
  created_at: string;
};

