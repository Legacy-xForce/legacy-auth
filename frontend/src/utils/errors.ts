import { ApiError } from "../api/client";

/** Only surface server messages; hide raw network/TypeError details from users. */
export function apiErrorMessage(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

/** The message shown for an error, falling back when it is not an Error. */
export function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message || fallback : fallback;
}

/**
 * WebAuthn errors carry a `name`; a cancelled prompt is not worth showing as a
 * raw exception. All three passkey screens use the same wording.
 */
export function describePasskeyError(err: any, fallback: string, cancelledMessage = "Passkey authentication was cancelled or timed out."): string {
  if (err?.name === "NotAllowedError") return cancelledMessage;
  if (err instanceof Error) return err.message || fallback;
  return err?.message || fallback;
}

/** "Enter your …" validation shared by the two sign-in screens and the forms. */
export function missingFields(...values: unknown[]): boolean {
  return values.some((value) => typeof value !== "string" || value.trim().length === 0);
}
