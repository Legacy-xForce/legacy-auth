<script setup lang="ts">
import Icon from "./Icon.vue";

// One setting: an icon, a title with a line of explanation, and its control on the right.
defineProps<{ icon?: string; title: string; description?: string; tone?: "accent" | "neutral" }>();
</script>

<template>
  <div class="flex items-center gap-3.5 px-5 py-4 sm:px-6">
    <div
      v-if="icon"
      class="flex size-10 shrink-0 items-center justify-center rounded-ui"
      :class="tone === 'accent' ? 'bg-accent/12 text-accent' : 'bg-fg/6 text-muted'"
    >
      <Icon :name="icon" :size="18" />
    </div>
    <div class="min-w-0 flex-1">
      <div class="text-body font-semibold text-fg">{{ title }}</div>
      <p v-if="description" class="m-0 mt-0.5 text-meta text-muted">{{ description }}</p>
    </div>
    <slot />
  </div>
</template>
