/** Shared labels and choices. One definition, so the console cannot drift between screens. */
export const APP_NAME = "Legacy Auth";

export const ROLES = ["admin", "user"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Record<Role, string> = {
  admin: "Admin",
  user: "Member",
};

export const ROLE_OPTIONS: { value: Role; label: string }[] = [
  { value: "user", label: ROLE_LABELS.user },
  { value: "admin", label: ROLE_LABELS.admin },
];

export const ROLE_FILTER_OPTIONS: { value: "" | Role; label: string }[] = [
  { value: "", label: "All" },
  { value: "admin", label: "Admins" },
  { value: "user", label: "Members" },
];

export type AppScopeKey = "calendar" | "tracker";

export const APP_SCOPES: { key: AppScopeKey; label: string; description: string; icon: string }[] = [
  { key: "calendar", label: "Calendar", description: "Legacy Calendar on the web and on phones.", icon: "calendar" },
  { key: "tracker", label: "Tracker", description: "Legacy Tracker on the web and on phones.", icon: "mapPin" },
];
