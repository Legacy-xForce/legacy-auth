<script setup lang="ts">
import { ref } from "vue";
import Icon from "./Icon.vue";

defineProps<{ modelValue: string }>();
defineEmits<{ "update:modelValue": [value: string] }>();
defineOptions({ inheritAttrs: false });

const visible = ref(false);
</script>

<template>
  <div class="relative min-w-0 flex-1">
    <input
      v-bind="$attrs"
      :value="modelValue"
      :type="visible ? 'text' : 'password'"
      class="pr-11"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
    <button
      type="button"
      class="icon-btn absolute top-1/2 right-1.5 size-8 -translate-y-1/2 rounded-[10px]"
      tabindex="-1"
      :aria-label="visible ? 'Hide password' : 'Show password'"
      :aria-pressed="visible"
      @click="visible = !visible"
    >
      <Icon :name="visible ? 'eyeOff' : 'eye'" :size="16" />
    </button>
  </div>
</template>
