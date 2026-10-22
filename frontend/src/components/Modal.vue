<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from "vue";

// A dialog frame: centered on wide screens, a bottom sheet on phones. Escape and a
// click on the backdrop close it unless it is busy.
const props = withDefaults(defineProps<{ open: boolean; labelledby?: string; busy?: boolean; width?: string }>(), {
  busy: false,
  width: "max-w-100",
});
const emit = defineEmits<{ close: [] }>();

const panel = ref<HTMLElement | null>(null);
let returnFocus: HTMLElement | null = null;

function close() {
  if (!props.busy) emit("close");
}

function onKeyDown(event: KeyboardEvent) {
  if (event.key === "Escape") close();
}

watch(
  () => props.open,
  async (open) => {
    if (open) {
      returnFocus = document.activeElement as HTMLElement | null;
      document.addEventListener("keydown", onKeyDown);
      await nextTick();
      const target = panel.value?.querySelector<HTMLElement>("[autofocus], input, button.btn-primary, button.btn-danger-solid") ?? panel.value;
      target?.focus();
    } else {
      document.removeEventListener("keydown", onKeyDown);
      returnFocus?.focus();
    }
  },
);

onBeforeUnmount(() => document.removeEventListener("keydown", onKeyDown));
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-end justify-center bg-mask p-0 backdrop-blur-[2px] sm:items-center sm:p-4"
        @click.self="close"
      >
        <div
          ref="panel"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="labelledby"
          tabindex="-1"
          class="modal-panel w-full rounded-t-3xl border border-b-0 border-line bg-raised p-6 pb-[max(1.5rem,env(safe-area-inset-bottom))] shadow-(--shadow-modal) outline-none sm:rounded-3xl sm:border-b"
          :class="width"
        >
          <slot />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-enter-active {
  transition: opacity 200ms var(--ease-out-quart);
}

.modal-leave-active {
  transition: opacity 140ms var(--ease-in-quart);
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-active .modal-panel {
  transition: transform 380ms var(--ease-out-expo);
}

.modal-leave-active .modal-panel {
  transition: transform 160ms var(--ease-in-quart);
}

.modal-enter-from .modal-panel,
.modal-leave-to .modal-panel {
  transform: translateY(100%);
}

@media (min-width: 640px) {
  .modal-enter-from .modal-panel,
  .modal-leave-to .modal-panel {
    transform: scale(0.96);
  }
}
</style>
