<script setup lang="ts">
import { computed } from "vue";
import Icon from "./Icon.vue";

const props = withDefaults(
  defineProps<{
    icon: string;
    title: string;
    description: string;
    actionLabel?: string;
    heading?: "h1" | "h2";
    tone?: "neutral" | "warning";
    surface?: boolean;
  }>(),
  { actionLabel: "", heading: "h2", tone: "neutral", surface: false }
);

const emit = defineEmits<{ action: [] }>();

const classes = computed(() =>
  props.surface
    ? "card flex flex-col items-center gap-4 p-7 text-center"
    : "flex flex-col items-center px-6 py-14 text-center"
);
const iconClass = computed(() =>
  props.tone === "warning" ? "bg-warning/12 text-warning" : "bg-fg/6 text-muted"
);
</script>

<template>
  <div :class="classes">
    <div class="flex size-12 items-center justify-center rounded-full" :class="iconClass">
      <Icon :name="icon" :size="20" />
    </div>
    <component :is="heading" class="m-0 mt-4 text-title">{{ title }}</component>
    <p class="m-0 mt-1 text-meta text-muted">{{ description }}</p>
    <button v-if="actionLabel" type="button" class="btn btn-secondary btn-sm mt-5" @click="emit('action')">
      {{ actionLabel }}
    </button>
  </div>
</template>
