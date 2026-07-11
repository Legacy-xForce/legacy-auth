<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ active: boolean }>();

const status = computed(() => {
  if (props.active) return { label: "Active", class: "text-success" };
  return { label: "Inactive", class: "text-text-dim" };
});
</script>

<template>
  <span class="inline-flex items-center gap-1.5 text-sm font-medium" :class="status.class">
    <span class="h-1.5 w-1.5 rounded-full bg-current" />
    {{ status.label }}
  </span>
</template>
