<script setup lang="ts">
import type { AppTheme } from "../theme/themes";

defineProps<{ theme: AppTheme }>();
</script>

<template>
  <!-- A tiny window in the theme's colors; Adaptive is split dark/light. -->
  <span
    class="flex size-7 shrink-0 items-center justify-center rounded-full border border-line"
    :style="
      theme.mode === 'system'
        ? { background: `linear-gradient(135deg, ${theme.preview.canvas} 0 50%, ${theme.preview.raised} 50% 100%)` }
        : { backgroundColor: theme.preview.canvas }
    "
  >
    <span
      v-if="theme.mode === 'system'"
      class="size-2.5 rounded-full border-2 border-white/80"
      :style="{ backgroundColor: theme.preview.accent }"
    />
    <span
      v-else
      class="flex size-4 flex-col items-center justify-center gap-[3px] rounded-[4px]"
      :style="{ backgroundColor: theme.preview.raised }"
    >
      <span class="h-[2.5px] w-2.5 rounded-full" :style="{ backgroundColor: theme.preview.accent }" />
      <span class="h-[2px] w-2 rounded-full" :style="{ backgroundColor: theme.preview.text }" />
    </span>
  </span>
</template>
