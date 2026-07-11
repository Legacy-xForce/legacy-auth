<script setup lang="ts">
import { Teleport, Transition } from "vue";
import Icon from "./Icon.vue";

withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    cancelLabel?: string;
    danger?: boolean;
    busy?: boolean;
  }>(),
  {
    confirmLabel: "Confirm",
    cancelLabel: "Cancel",
    danger: false,
    busy: false,
  }
);

const emit = defineEmits<{ confirm: []; cancel: [] }>();
</script>

<template>
  <Teleport to="body">
    <Transition name="confirm-fade">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" @click.self="emit('cancel')">
        <div class="card w-full max-w-90 p-6 shadow-2xl">
          <div class="mb-4 flex items-center gap-3">
            <div
              class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
              :class="danger ? 'bg-danger-soft text-danger' : 'bg-accent-soft text-accent'"
            >
              <Icon name="alertTriangle" :size="18" />
            </div>
            <h3 class="m-0 text-base font-bold">{{ title }}</h3>
          </div>
          <p class="m-0 mb-6 text-sm text-text-muted">{{ message }}</p>
          <div class="flex justify-end gap-2.5">
            <button class="btn btn-ghost" :disabled="busy" @click="emit('cancel')">{{ cancelLabel }}</button>
            <button class="btn" :class="danger ? 'btn-danger-solid' : 'btn-primary'" :disabled="busy" @click="emit('confirm')">
              {{ busy ? "Please wait…" : confirmLabel }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.confirm-fade-enter-active,
.confirm-fade-leave-active {
  transition: opacity 0.15s ease;
}
.confirm-fade-enter-from,
.confirm-fade-leave-to {
  opacity: 0;
}
.confirm-fade-enter-active .card,
.confirm-fade-leave-active .card {
  transition: transform 0.15s ease;
}
.confirm-fade-enter-from .card,
.confirm-fade-leave-to .card {
  transform: scale(0.96);
}
</style>
