import type { UserRecord } from "../types.ts";

/** The user shape every profile/admin response returns — no password hash. */
export function toPublicUser(user: UserRecord) {
  return {
    id: user.id,
    username: user.username,
    display_name: user.display_name,
    role: user.role,
    active: user.active,
    scopes: user.scopes,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}
