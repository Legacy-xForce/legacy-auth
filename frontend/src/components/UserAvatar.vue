<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { avatarUrl } from "../api/client";
import Icon from "./Icon.vue";

const props = withDefaults(defineProps<{ userId: string; name?: string; size?: number }>(), { size: 40 });

const failed = ref(false);
watch(
  () => props.userId,
  () => {
    failed.value = false;
  }
);

const initial = computed(() => props.name?.trim().charAt(0).toUpperCase() ?? "");
</script>

<template>
  <div
    class="flex shrink-0 items-center justify-center overflow-hidden rounded-full bg-accent/14 font-semibold text-accent ring-1 ring-fg/8 select-none"
    :style="{ width: size + 'px', height: size + 'px', fontSize: Math.round(size * 0.4) + 'px' }"
  >
    <img v-if="!failed" :src="avatarUrl(userId)" alt="" class="size-full object-cover" @error="failed = true" />
    <span v-else-if="initial" aria-hidden="true">{{ initial }}</span>
    <Icon v-else name="user" :size="Math.round(size * 0.5)" />
  </div>
</template>
