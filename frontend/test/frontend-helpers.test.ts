import { describe, expect, test } from "bun:test";
import { APP_SCOPES, ROLE_FILTER_OPTIONS, ROLE_LABELS, ROLE_OPTIONS } from "../src/constants";
import { apiErrorMessage, describePasskeyError, errorMessage, missingFields } from "../src/utils/errors";
import { getTheme, isThemeId, resolvedThemeId, THEME_IDS, THEMES } from "../src/theme/themes";
import { avatarUrl, fetchJson, ApiError } from "../src/api/client";
import { useCopyToClipboard } from "../src/composables/useCopyToClipboard";

describe("shared console constants", () => {
  test("role labels and options come from one place", () => {
    expect(ROLE_LABELS).toEqual({ admin: "Admin", user: "Member" });
    expect(ROLE_OPTIONS.map((option) => option.value)).toEqual(["user", "admin"]);
    expect(ROLE_FILTER_OPTIONS.map((option) => option.value)).toEqual(["", "admin", "user"]);
    expect(ROLE_OPTIONS.every((option) => option.label === ROLE_LABELS[option.value])).toBe(true);
  });

  test("the app scopes drive both user forms", () => {
    expect(APP_SCOPES.map((scope) => scope.key)).toEqual(["calendar", "tracker"]);
    expect(APP_SCOPES.every((scope) => scope.label && scope.description && scope.icon)).toBe(true);
  });
});

describe("error helpers", () => {
  test("errorMessage uses the Error message and otherwise the fallback", () => {
    expect(errorMessage(new Error("boom"), "fallback")).toBe("boom");
    expect(errorMessage("boom", "fallback")).toBe("fallback");
    expect(errorMessage(null, "fallback")).toBe("fallback");
  });

  test("apiErrorMessage hides raw network errors but keeps server messages", () => {
    expect(apiErrorMessage(new ApiError("Invalid credentials", 401), "Unable to sign in.")).toBe("Invalid credentials");
    expect(apiErrorMessage(new Error("Failed to fetch"), "Unable to sign in.")).toBe("Unable to sign in.");
  });

  test("a cancelled passkey prompt gets the localised wording", () => {
    expect(describePasskeyError({ name: "NotAllowedError" }, "fallback")).toBe("Passkey authentication was cancelled or timed out.");
    expect(describePasskeyError({ name: "NotAllowedError" }, "fallback", "Cancelled.")).toBe("Cancelled.");
    expect(describePasskeyError(new Error("other"), "fallback")).toBe("other");
    expect(describePasskeyError(undefined, "fallback")).toBe("fallback");
  });

  test("missingFields treats whitespace-only values as missing", () => {
    expect(missingFields("alice", "secret")).toBe(false);
    expect(missingFields("  ", "secret")).toBe(true);
    expect(missingFields("alice", undefined)).toBe(true);
  });
});

describe("theme bootstrap", () => {
  test("theme ids are unique and resolve adaptively", () => {
    expect(THEME_IDS).toEqual(THEMES.map((theme) => theme.id));
    expect(new Set(THEME_IDS).size).toBe(THEME_IDS.length);
    expect(isThemeId("oled")).toBe(true);
    expect(isThemeId("nope")).toBe(false);
    expect(getTheme("oled").label).toBe("OLED");
    expect(resolvedThemeId("adaptive", true)).toBe("catppuccin-latte");
    expect(resolvedThemeId("adaptive", false)).toBe("oled");
    expect(resolvedThemeId("catppuccin-mocha", true)).toBe("catppuccin-mocha");
  });

  test("index.html's pre-paint table matches THEMES", async () => {
    const html = await Bun.file(new URL("../index.html", import.meta.url)).text();
    const entries = [...html.matchAll(/"?([\w-]+)"?:\s*\["(#[0-9a-f]{6})",\s*"(dark|light)"\]/gi)].map((match) => ({
      id: match[1],
      canvas: match[2].toLowerCase(),
      mode: match[3],
    }));
    expect(entries.map((entry) => entry.id)).toEqual(THEME_IDS);
    for (const theme of THEMES) {
      const entry = entries.find((candidate) => candidate.id === theme.id)!;
      expect(entry.canvas).toBe(theme.preview.canvas.toLowerCase());
      expect(entry.mode).toBe(theme.mode === "light" ? "light" : "dark");
    }
  });

  test("the picker previews are still in the stylesheet", async () => {
    const css = await Bun.file(new URL("../src/style.css", import.meta.url)).text();
    const colors = new Set(THEMES.flatMap((theme) => Object.values(theme.preview).map((color) => color.toLowerCase())));
    for (const color of colors) expect(css.toLowerCase()).toContain(color);
  });
});

describe("api client helpers", () => {
  test("avatarUrl adds a cache-busting version when given", () => {
    expect(avatarUrl("abc")).toBe("/auth/profile-picture/abc");
    expect(avatarUrl("abc", 3)).toBe("/auth/profile-picture/abc?v=3");
  });

  test("fetchJson throws the given error class with the server message", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ error: "nope" }), { status: 403 })) as typeof fetch;
    try {
      await expect(fetchJson("/x", {}, ApiError)).rejects.toMatchObject({ message: "nope", status: 403 });
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("clipboard composable", () => {
  test("copy reports success and flips the Copied flag for the duration", async () => {
    const written: string[] = [];
    const original = globalThis.navigator.clipboard;
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (value: string) => { written.push(value); } },
    });
    try {
      const { copied, copy } = useCopyToClipboard(20, false);
      expect(await copy("secret")).toBe(true);
      expect(written).toEqual(["secret"]);
      expect(copied.value).toBe(true);
      await Bun.sleep(40);
      expect(copied.value).toBe(false);
      expect(await copy("")).toBe(false);
    } finally {
      Object.defineProperty(globalThis.navigator, "clipboard", { configurable: true, value: original });
    }
  });

  test("a denied clipboard does not report success", async () => {
    const original = globalThis.navigator.clipboard;
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => { throw new Error("denied"); } },
    });
    try {
      const { copied, copy } = useCopyToClipboard(20, false);
      expect(await copy("secret")).toBe(false);
      expect(copied.value).toBe(false);
    } finally {
      Object.defineProperty(globalThis.navigator, "clipboard", { configurable: true, value: original });
    }
  });
});
