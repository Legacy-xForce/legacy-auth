<script setup lang="ts">
defineProps<{ modelValue: boolean; disabled?: boolean }>();
defineEmits<{ "update:modelValue": [value: boolean] }>();
</script>

<template>
  <button
    type="button"
    class="flex h-5.5 w-10 shrink-0 items-center justify-start rounded-full border border-border-strong bg-bg-input p-0.5 transition-colors duration-150"
    :class="{ 'justify-end! border-accent! bg-accent!': modelValue }"
    :disabled="disabled"
    role="switch"
    :aria-checked="modelValue"
    @click="$emit('update:modelValue', !modelValue)"
  >
    <span class="block h-4 w-4 rounded-full bg-white shadow-[0_1px_2px_rgba(0,0,0,0.3)]" />
  </button>
</template>
