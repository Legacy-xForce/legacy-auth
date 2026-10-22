import { defineStore } from "pinia";
import { ref } from "vue";
import { applyTheme, getStoredTheme, setTheme as persistTheme, type ThemeId } from "../theme/themes";

/** The selected theme, kept on this device only. */
export const useAppearanceStore = defineStore("appearance", () => {
  const theme = ref<ThemeId>(getStoredTheme());
  applyTheme(theme.value);

  function setTheme(id: ThemeId) {
    theme.value = persistTheme(id);
  }

  return { theme, setTheme };
});
