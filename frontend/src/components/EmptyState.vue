<script setup lang="ts">
import Icon from "./Icon.vue";

withDefaults(
  defineProps<{
    icon: string;
    title: string;
    description: string;
    actionLabel?: string;
    heading?: "h1" | "h2";
  }>(),
  { actionLabel: "", heading: "h2" }
);

const emit = defineEmits<{ action: [] }>();
</script>

<template>
  <div class="flex flex-col items-center px-6 py-14 text-center">
    <div class="flex size-12 items-center justify-center rounded-full bg-fg/6 text-muted">
      <Icon :name="icon" :size="20" />
    </div>
    <component :is="heading" class="m-0 mt-4 text-title">{{ title }}</component>
    <p class="m-0 mt-1 text-meta text-muted">{{ description }}</p>
    <button v-if="actionLabel" type="button" class="btn btn-secondary btn-sm mt-5" @click="emit('action')">
      {{ actionLabel }}
    </button>
  </div>
</template>
