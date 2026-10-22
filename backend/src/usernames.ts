/**
 * Usernames are login identifiers: always trimmed and lowercased, so a person
 * can type their name with any capitalization and still reach the same account.
 * The name as typed is kept separately as the display name.
 */
export function normalizeUsername(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

/** The human-facing name, with the capitalization the person used. */
export function displayNameFromInput(value: unknown): string {
  return String(value ?? "").trim();
}
