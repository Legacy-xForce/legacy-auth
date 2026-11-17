<script setup lang="ts">
import { generatePassword } from "../utils/password";
import { useCopyToClipboard } from "../composables/useCopyToClipboard";
import Icon from "./Icon.vue";
import PasswordInput from "./PasswordInput.vue";

/** Password input with generate/copy buttons. Both user forms use the same one. */
withDefaults(
  defineProps<{
    id: string;
    placeholder?: string;
    autocomplete?: string;
    showCopied?: boolean;
  }>(),
  { placeholder: "", autocomplete: "off", showCopied: true }
);

const model = defineModel<string>({ required: true });
const { copied, copy } = useCopyToClipboard();

function fill() {
  model.value = generatePassword();
}

async function copyPassword() {
  if (!model.value) return;
  await copy(model.value, "Password copied");
}
</script>

<template>
  <div class="flex gap-2">
    <PasswordInput
      :id="id"
      v-model="model"
      class="input font-mono placeholder:font-sans"
      :placeholder="placeholder"
      :autocomplete="autocomplete"
      data-form-type="other"
      data-lpignore="true"
      data-1p-ignore
      data-bwignore="true"
    />
    <button type="button" class="btn btn-secondary h-11 px-3.5" title="Generate a password" @click="fill">
      <Icon name="dice" :size="16" />
      <span class="hidden sm:inline">Generate</span>
    </button>
    <button
      type="button"
      class="btn btn-secondary h-11 w-11 px-0"
      :title="copied && showCopied ? 'Copied' : 'Copy password'"
      :aria-label="copied && showCopied ? 'Copied' : 'Copy password'"
      :disabled="!model"
      @click="copyPassword"
    >
      <Icon :name="copied && showCopied ? 'check' : 'copy'" :size="16" :class="{ 'text-success': copied && showCopied }" />
    </button>
  </div>
</template>
