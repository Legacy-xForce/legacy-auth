<script setup lang="ts">
import { ref, watch } from "vue";
import { avatarUrl } from "../api/client";
import Icon from "./Icon.vue";

const props = withDefaults(defineProps<{ userId: string; size?: number }>(), { size: 40 });

const failed = ref(false);
watch(
  () => props.userId,
  () => {
    failed.value = false;
  }
);
</script>

<template>
  <div
    class="flex shrink-0 items-center justify-center overflow-hidden rounded-full border border-border bg-bg-input text-text-dim"
    :style="{ width: size + 'px', height: size + 'px' }"
  >
    <img v-if="!failed" :src="avatarUrl(userId)" alt="" class="h-full w-full object-cover" @error="failed = true" />
    <Icon v-else name="user" :size="Math.round(size * 0.55)" />
  </div>
</template>
