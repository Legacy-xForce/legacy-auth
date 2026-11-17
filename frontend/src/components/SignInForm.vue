<script setup lang="ts">
import { ref, watch } from "vue";
import FormAlert from "./FormAlert.vue";
import Icon from "./Icon.vue";
import PasswordInput from "./PasswordInput.vue";

/** The password + passkey form shared by the console login and the OP's sign-in page. */
const props = withDefaults(
  defineProps<{
    passkeySupported?: boolean;
    loading?: boolean;
    passkeyLoading?: boolean;
    cancelling?: boolean;
    error?: string;
    usernameAutocomplete?: string;
    initialUsername?: string;
    errorTestId?: boolean;
  }>(),
  {
    passkeySupported: true,
    loading: false,
    passkeyLoading: false,
    cancelling: false,
    error: "",
    usernameAutocomplete: "username",
    initialUsername: "",
    errorTestId: false,
  }
);

const emit = defineEmits<{
  submit: [username: string, password: string];
  invalid: [];
  passkey: [username: string | undefined];
}>();

const username = ref(props.initialUsername);
const password = ref("");

watch(
  () => props.initialUsername,
  (value) => {
    if (value && !username.value) username.value = value;
  }
);

function onSubmit() {
  if (!username.value.trim() || !password.value) {
    emit("invalid");
    return;
  }
  emit("submit", username.value.trim(), password.value);
}

function onPasskey() {
  emit("passkey", username.value.trim() || undefined);
}

</script>

<template>
  <form class="card flex flex-col gap-4 p-6 sm:p-7" novalidate @submit.prevent="onSubmit">
    <div class="field">
      <label for="username">Username</label>
      <div class="input-wrap">
        <Icon name="at" />
        <input
          id="username"
          v-model="username"
          class="input"
          placeholder="Your username"
          :autocomplete="usernameAutocomplete"
          autocapitalize="none"
          spellcheck="false"
          autofocus
        />
      </div>
    </div>

    <div class="field">
      <label for="password">Password</label>
      <div class="input-wrap">
        <Icon name="lock" />
        <PasswordInput
          id="password"
          v-model="password"
          class="input"
          placeholder="Your password"
          autocomplete="current-password"
        />
      </div>
    </div>

    <FormAlert v-if="error" :data-testid="errorTestId ? 'error' : undefined">{{ error }}</FormAlert>

    <button type="submit" class="btn btn-primary btn-lg mt-1 w-full" :disabled="loading || passkeyLoading || cancelling">
      <Icon v-if="loading" name="loader" :size="18" />
      {{ loading ? "Signing in…" : "Sign in" }}
      <Icon v-if="!loading" name="arrowRight" :size="18" />
    </button>

    <template v-if="passkeySupported">
      <div class="flex items-center gap-3 text-xs font-medium text-subtle">
        <span class="h-px flex-1 bg-line" />
        or
        <span class="h-px flex-1 bg-line" />
      </div>

      <button
        type="button"
        class="btn btn-secondary btn-lg w-full"
        :disabled="loading || passkeyLoading || cancelling"
        @click="onPasskey"
      >
        <Icon :name="passkeyLoading ? 'loader' : 'fingerprint'" :size="18" />
        {{ passkeyLoading ? "Waiting for your passkey…" : "Sign in with a passkey" }}
      </button>
    </template>
  </form>
</template>
