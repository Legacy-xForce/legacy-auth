<script setup lang="ts">
import Icon from "./Icon.vue";

withDefaults(defineProps<{ tone?: "danger" | "success" | "info" }>(), { tone: "danger" });
</script>

<template>
  <div
    :role="tone === 'danger' ? 'alert' : 'status'"
    class="flex animate-fade-in items-start gap-2.5 rounded-ui border px-3.5 py-2.5 text-meta"
    :class="{
      'border-danger/25 bg-danger/10 text-danger': tone === 'danger',
      'border-success/25 bg-success/10 text-success': tone === 'success',
      'border-line bg-fg/4 text-muted': tone === 'info',
    }"
  >
    <Icon :name="tone === 'success' ? 'checkCircle' : tone === 'info' ? 'info' : 'alertCircle'" :size="16" class="mt-px shrink-0" />
    <span class="min-w-0"><slot /></span>
  </div>
</template>
