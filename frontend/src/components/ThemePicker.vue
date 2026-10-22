<script setup lang="ts">
import { useAppearanceStore } from "../stores/appearance";
import { THEMES, type AppTheme } from "../theme/themes";
import Icon from "./Icon.vue";
import ThemeSwatch from "./ThemeSwatch.vue";

// `list` stacks the themes for a narrow menu; `pills` wraps them for a settings section.
withDefaults(defineProps<{ layout?: "pills" | "list" }>(), { layout: "pills" });

const appearance = useAppearanceStore();

function modeLabel(theme: AppTheme) {
  return theme.mode === "system" ? "follows the system" : theme.mode;
}
</script>

<template>
  <div
    role="radiogroup"
    aria-label="Theme"
    :class="layout === 'pills' ? 'flex flex-wrap gap-2' : 'flex flex-col gap-0.5'"
  >
    <button
      v-for="option in THEMES"
      :key="option.id"
      type="button"
      role="radio"
      :aria-checked="appearance.theme === option.id"
      :aria-label="`${option.label}, ${modeLabel(option)}`"
      class="pressable flex cursor-pointer items-center gap-2.5 text-left"
      :class="[
        layout === 'pills'
          ? 'min-h-10 rounded-full border py-1 pr-3 pl-1.5'
          : 'min-h-11 w-full rounded-ui border border-transparent px-2',
        appearance.theme === option.id
          ? layout === 'pills'
            ? 'border-accent bg-accent/12 text-fg'
            : 'bg-accent/12 text-fg'
          : layout === 'pills'
            ? 'border-line bg-raised text-muted hover:bg-fg/6 hover:text-fg'
            : 'text-muted hover:bg-fg/6 hover:text-fg',
      ]"
      @click="appearance.setTheme(option.id)"
    >
      <ThemeSwatch :theme="option" />
      <span class="text-meta font-medium whitespace-nowrap" :class="{ 'flex-1': layout === 'list' }">
        {{ layout === "list" ? option.label : option.shortLabel }}
      </span>
      <Icon v-if="appearance.theme === option.id" name="check" :size="14" class="text-accent" />
    </button>
  </div>
</template>
