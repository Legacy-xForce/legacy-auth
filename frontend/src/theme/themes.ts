export type ThemeId = "oled" | "catppuccin-mocha" | "catppuccin-macchiato" | "catppuccin-frappe" | "catppuccin-latte" | "adaptive";

export type ThemeMode = "dark" | "light" | "system";

export interface AppTheme {
  id: ThemeId;
  /** Full name used in accessibility labels. */
  label: string;
  /** Short name shown on the theme pill. */
  shortLabel: string;
  mode: ThemeMode;
  /** Representative colors used by the theme picker preview. */
  preview: {
    canvas: string;
    raised: string;
    accent: string;
    text: string;
  };
}

export const THEME_STORAGE_KEY = "pref_theme";
export const DEFAULT_THEME_ID: ThemeId = "oled";

// Keep the previews in sync with the `data-theme` blocks in style.css, and the ids
// with the pre-paint script in index.html.
export const THEMES: AppTheme[] = [
  {
    id: "oled",
    label: "OLED",
    shortLabel: "OLED",
    mode: "dark",
    preview: { canvas: "#000000", raised: "#0e0d12", accent: "#a78bfa", text: "#f6f5fa" },
  },
  {
    id: "catppuccin-mocha",
    label: "Catppuccin Mocha",
    shortLabel: "Mocha",
    mode: "dark",
    preview: { canvas: "#11111b", raised: "#1e1e2e", accent: "#cba6f7", text: "#cdd6f4" },
  },
  {
    id: "catppuccin-macchiato",
    label: "Catppuccin Macchiato",
    shortLabel: "Macchiato",
    mode: "dark",
    preview: { canvas: "#181926", raised: "#24273a", accent: "#c6a0f6", text: "#cad3f5" },
  },
  {
    id: "catppuccin-frappe",
    label: "Catppuccin Frappé",
    shortLabel: "Frappé",
    mode: "dark",
    preview: { canvas: "#232634", raised: "#303446", accent: "#ca9ee6", text: "#c6d0f5" },
  },
  {
    id: "catppuccin-latte",
    label: "Catppuccin Latte",
    shortLabel: "Latte",
    mode: "light",
    preview: { canvas: "#e6e9ef", raised: "#eff1f5", accent: "#8839ef", text: "#4c4f69" },
  },
  {
    id: "adaptive",
    label: "Adaptive",
    shortLabel: "Adaptive",
    mode: "system",
    preview: { canvas: "#000000", raised: "#eff1f5", accent: "#a78bfa", text: "#4c4f69" },
  },
];

const themeIds = new Set<string>(THEMES.map((theme) => theme.id));
const lightQuery = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: light)") : null;

export function isThemeId(value: unknown): value is ThemeId {
  return typeof value === "string" && themeIds.has(value);
}

export function getTheme(id: ThemeId): AppTheme {
  return THEMES.find((theme) => theme.id === id) ?? THEMES[0];
}

export function getStoredTheme(): ThemeId {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeId(stored) ? stored : DEFAULT_THEME_ID;
  } catch {
    return DEFAULT_THEME_ID;
  }
}

/** Adaptive is OLED in a dark system and Latte in a light one; every other theme is itself. */
function resolveTheme(id: ThemeId): AppTheme {
  if (id !== "adaptive") return getTheme(id);
  return getTheme(lightQuery?.matches ? "catppuccin-latte" : "oled");
}

let selected: ThemeId = DEFAULT_THEME_ID;

/**
 * Applies a theme to the document. The colors live in `style.css` under
 * `html[data-theme='…']`, so this only flips the selector and keeps the
 * browser chrome (color scheme / theme-color) in sync.
 */
export function applyTheme(id: ThemeId): void {
  selected = id;
  const theme = resolveTheme(id);
  const mode = theme.mode === "light" ? "light" : "dark";
  const root = document.documentElement;

  root.dataset.theme = theme.id;
  root.style.colorScheme = mode;

  document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", mode);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme.preview.canvas);
}

// Adaptive follows the system as it changes, not only when the page loads.
lightQuery?.addEventListener("change", () => {
  if (selected === "adaptive") applyTheme(selected);
});

export function setTheme(id: ThemeId): ThemeId {
  applyTheme(id);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, id);
  } catch {
    // Storage can be unavailable (private mode, blocked site data); the choice still applies this session.
  }
  return id;
}
