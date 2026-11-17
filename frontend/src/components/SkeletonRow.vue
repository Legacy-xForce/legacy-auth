<script setup lang="ts">
withDefaults(
  defineProps<{ size?: number; rounded?: "full" | "ui"; lines?: number; wide?: number }>(),
  { size: 40, rounded: "full", lines: 2, wide: 176 }
);
</script>

<template>
  <span class="flex items-center gap-3" aria-hidden="true">
    <span
      class="shrink-0 animate-pulse bg-fg/8"
      :class="rounded === 'full' ? 'rounded-full' : 'rounded-ui'"
      :style="{ width: size + 'px', height: size + 'px' }"
    />
    <span class="flex flex-col gap-2">
      <span class="h-3 w-28 animate-pulse rounded-full bg-fg/8" />
      <span v-if="lines > 1" class="h-2.5 animate-pulse rounded-full bg-fg/5" :style="{ width: wide + 'px' }" />
    </span>
  </span>
</template>
