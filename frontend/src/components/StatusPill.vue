<script setup lang="ts">
defineProps<{ active: boolean }>();
</script>

<template>
  <span class="chip" :class="active ? 'bg-success/12 text-success' : 'bg-fg/6 text-subtle'">
    <span class="size-1.5 rounded-full bg-current" />
    {{ active ? "Active" : "Disabled" }}
  </span>
</template>
