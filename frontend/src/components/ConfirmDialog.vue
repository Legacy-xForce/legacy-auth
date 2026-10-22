<script setup lang="ts">
import Icon from "./Icon.vue";
import Modal from "./Modal.vue";

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
  <Modal :open="open" :busy="busy" labelledby="confirm-title" @close="emit('cancel')">
    <div
      class="mb-4 flex size-11 items-center justify-center rounded-full"
      :class="danger ? 'bg-danger/12 text-danger' : 'bg-accent/12 text-accent'"
    >
      <Icon :name="danger ? 'alertTriangle' : 'info'" :size="20" />
    </div>
    <h2 id="confirm-title" class="m-0 text-headline">{{ title }}</h2>
    <p class="m-0 mt-2 text-body text-muted">{{ message }}</p>
    <div class="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
      <button type="button" class="btn btn-secondary" :disabled="busy" @click="emit('cancel')">{{ cancelLabel }}</button>
      <button
        type="button"
        class="btn"
        :class="danger ? 'btn-danger-solid' : 'btn-primary'"
        :disabled="busy"
        @click="emit('confirm')"
      >
        <Icon v-if="busy" name="loader" :size="16" />
        {{ confirmLabel }}
      </button>
    </div>
  </Modal>
</template>
