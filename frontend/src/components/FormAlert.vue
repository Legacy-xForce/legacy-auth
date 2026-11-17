<script setup lang="ts">
import Icon from "./Icon.vue";

// Every call site uses the default danger tone; success/info were never passed.
withDefaults(defineProps<{ tone?: "danger" }>(), { tone: "danger" });
</script>

<template>
  <div
    role="alert"
    class="flex animate-fade-in items-start gap-2.5 rounded-ui border border-danger/25 bg-danger/10 px-3.5 py-2.5 text-meta text-danger"
  >
    <Icon name="alertCircle" :size="16" class="mt-px shrink-0" />
    <span class="min-w-0"><slot /></span>
  </div>
</template>
