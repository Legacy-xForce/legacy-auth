<script setup lang="ts">
import { useToastStore } from "../stores/toast";
import Icon from "./Icon.vue";

const toast = useToastStore();
</script>

<template>
  <div
    class="pointer-events-none fixed inset-x-3 top-[max(0.75rem,env(safe-area-inset-top))] z-[60] flex flex-col items-center gap-2 sm:inset-x-auto sm:top-auto sm:right-6 sm:bottom-6 sm:items-end"
    aria-live="polite"
  >
    <TransitionGroup name="pop">
      <div
        v-for="item in toast.toasts"
        :key="item.id"
        class="pointer-events-auto flex w-full max-w-88 items-center gap-3 rounded-2xl border border-line bg-overlay py-3 pr-2 pl-4 shadow-(--shadow-overlay)"
        :role="item.tone === 'error' ? 'alert' : 'status'"
      >
        <Icon
          :name="item.tone === 'error' ? 'alertCircle' : item.tone === 'info' ? 'info' : 'checkCircle'"
          :size="18"
          class="shrink-0"
          :class="{ 'text-danger': item.tone === 'error', 'text-success': item.tone === 'success', 'text-accent': item.tone === 'info' }"
        />
        <span class="min-w-0 flex-1 text-meta font-medium text-fg">{{ item.message }}</span>
        <button type="button" class="icon-btn size-7 rounded-lg" aria-label="Dismiss" @click="toast.dismiss(item.id)">
          <Icon name="x" :size="14" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>
