<script setup lang="ts">
import { ref } from "vue";
import Icon from "./Icon.vue";

defineProps<{ modelValue: string }>();
defineEmits<{ "update:modelValue": [value: string] }>();
defineOptions({ inheritAttrs: false });

const visible = ref(false);
</script>

<template>
  <div class="relative flex-1">
    <input
      v-bind="$attrs"
      :value="modelValue"
      :type="visible ? 'text' : 'password'"
      class="pr-9"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
    <button
      type="button"
      class="icon-btn absolute right-1 top-1/2 h-7 w-7 -translate-y-1/2"
      tabindex="-1"
      :aria-label="visible ? 'Hide password' : 'Show password'"
      :aria-pressed="visible"
      @click="visible = !visible"
    >
      <Icon :name="visible ? 'eyeOff' : 'eye'" :size="15" />
    </button>
  </div>
</template>
