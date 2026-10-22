<script setup lang="ts">
defineProps<{ modelValue: boolean; disabled?: boolean }>();
defineEmits<{ "update:modelValue": [value: boolean] }>();
</script>

<template>
  <button
    type="button"
    class="relative inline-flex h-6.5 w-11 shrink-0 cursor-pointer items-center rounded-full p-0.75 transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-50"
    :class="modelValue ? 'bg-primary' : 'bg-fg/15 hover:not-disabled:bg-fg/20'"
    :disabled="disabled"
    role="switch"
    :aria-checked="modelValue"
    @click="$emit('update:modelValue', !modelValue)"
  >
    <span
      class="block size-5 rounded-full shadow-[0_1px_3px_rgb(0_0_0/0.3)] transition-transform duration-200 ease-(--ease-out-expo)"
      :class="modelValue ? 'translate-x-4.5 bg-primary-contrast' : 'translate-x-0 bg-white'"
    />
  </button>
</template>
