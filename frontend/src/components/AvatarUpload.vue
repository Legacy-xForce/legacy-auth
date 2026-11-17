<script setup lang="ts">
import { ref } from "vue";
import { api } from "../api/client";
import { useToastStore } from "../stores/toast";
import { errorMessage } from "../utils/errors";
import Icon from "./Icon.vue";
import UserAvatar from "./UserAvatar.vue";

/** The avatar button + hidden file input, shared by the user editor and Settings. */
const props = withDefaults(
  defineProps<{ userId: string; name: string; endpoint: string; size?: number }>(),
  { size: 72 }
);
const emit = defineEmits<{ error: [message: string]; uploaded: [] }>();

const toast = useToastStore();
const input = ref<HTMLInputElement | null>(null);
const version = ref(0);

function trigger() {
  input.value?.click();
}

async function onSelected(event: Event) {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);
  try {
    await api.postForm(props.endpoint, formData);
    version.value++;
    toast.success("Picture updated");
    emit("uploaded");
  } catch (err) {
    const message = errorMessage(err, "Failed to upload avatar");
    toast.error(message);
    emit("error", message);
  } finally {
    target.value = "";
  }
}
</script>

<template>
  <button
    type="button"
    class="group relative shrink-0 cursor-pointer rounded-full"
    aria-label="Change profile picture"
    @click="trigger"
  >
    <UserAvatar :user-id="userId" :name="name" :size="size" :version="version" />
    <span
      class="absolute -right-0.5 -bottom-0.5 flex size-7 items-center justify-center rounded-full border-[3px] border-canvas bg-primary text-primary-contrast transition-transform group-hover:scale-110"
    >
      <Icon name="camera" :size="13" />
    </span>
  </button>
  <input ref="input" type="file" accept="image/*" class="hidden" @change="onSelected" />
</template>
