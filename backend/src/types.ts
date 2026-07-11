export type UserRole = "admin" | "user";

export type UserScopes = {
  calendar: boolean;
  tracker: boolean;
};

export type UserRecord = {
  id: string;
  username: string;
  password_hash: string;
  role: UserRole;
  active: boolean;
  locked: boolean;
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
