<script setup lang="ts" generic="T extends string">
// A small set of mutually exclusive choices, shown side by side (role filter, user role).
defineProps<{ options: { value: T; label: string }[]; label: string }>();
const model = defineModel<T>({ required: true });
</script>

<template>
  <div role="radiogroup" :aria-label="label" class="inline-flex h-11 shrink-0 gap-0.5 rounded-ui bg-fg/6 p-1">
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      role="radio"
      :aria-checked="model === option.value"
      class="pressable flex flex-1 cursor-pointer items-center justify-center rounded-[9px] px-3.5 text-meta font-semibold whitespace-nowrap"
      :class="model === option.value ? 'bg-selected text-fg shadow-[0_1px_3px_rgb(0_0_0/0.18)]' : 'text-muted hover:text-fg'"
      @click="model = option.value"
    >
      {{ option.label }}
    </button>
  </div>
</template>
