<script setup lang="ts">
import { ref } from "vue";
import { useDismiss } from "../composables/useDismiss";
import Icon from "./Icon.vue";
import ThemePicker from "./ThemePicker.vue";

// The theme switch on the sign-in pages, where there is no settings screen to hold it.
const open = ref(false);
const root = ref<HTMLElement | null>(null);
useDismiss(root, open);
</script>

<template>
  <div ref="root" class="relative">
    <button
      type="button"
      class="icon-btn size-10 rounded-full border border-line bg-raised/70 backdrop-blur"
      aria-label="Appearance"
      aria-haspopup="dialog"
      :aria-expanded="open"
      @click="open = !open"
    >
      <Icon name="palette" :size="18" />
    </button>
    <Transition name="pop">
      <div
        v-if="open"
        role="dialog"
        aria-label="Appearance"
        class="absolute top-[calc(100%+0.5rem)] right-0 z-30 w-64 origin-top-right rounded-2xl border border-line bg-overlay p-1.5 shadow-(--shadow-overlay)"
      >
        <p class="eyebrow m-0 px-2 pt-1.5 pb-2">Appearance</p>
        <ThemePicker layout="list" />
        <p class="m-0 px-2 pt-2 pb-1 text-xs text-subtle">Saved on this device only.</p>
      </div>
    </Transition>
  </div>
</template>
