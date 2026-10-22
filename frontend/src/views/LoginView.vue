<script setup lang="ts">
import { ref } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useAuthStore } from "../stores/auth";
import { ApiError } from "../api/client";
import { isPasskeySupported } from "../services/webauthn";
import AuthShell from "../components/AuthShell.vue";
import FormAlert from "../components/FormAlert.vue";
import Icon from "../components/Icon.vue";
import PasswordInput from "../components/PasswordInput.vue";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const passkeySupported = isPasskeySupported();

const username = ref("");
const password = ref("");
const error = ref("");
const loading = ref(false);
const passkeyLoading = ref(false);

async function onSubmit() {
  error.value = "";
  if (!username.value || !password.value) {
    error.value = "Enter your username and password.";
    return;
  }
  loading.value = true;
  try {
    await auth.login(username.value, password.value);
    const redirect = typeof route.query.redirect === "string" ? route.query.redirect : "/";
    router.push(redirect);
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : "Unable to sign in.";
  } finally {
    loading.value = false;
  }
}

async function handlePasskeyLogin() {
  error.value = "";
  passkeyLoading.value = true;
  try {
    const success = await auth.loginWithPasskey(username.value.trim() || undefined);
    if (success) {
      const redirect = typeof route.query.redirect === "string" ? route.query.redirect : "/";
      router.push(redirect);
    }
  } catch (err: any) {
    if (err?.name === "NotAllowedError") {
      error.value = "Passkey authentication was cancelled or timed out.";
    } else {
      error.value = err instanceof ApiError ? err.message : (err?.message || "Passkey sign-in failed.");
    }
  } finally {
    passkeyLoading.value = false;
  }
}
</script>

<template>
  <AuthShell title="Legacy Auth">
    <template #subtitle>
      <p class="m-0 mt-1.5 text-body text-muted">Sign in to manage your Legacy account.</p>
    </template>

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
            autocomplete="username"
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

      <FormAlert v-if="error">{{ error }}</FormAlert>

      <button type="submit" class="btn btn-primary btn-lg mt-1 w-full" :disabled="loading || passkeyLoading">
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
          :disabled="loading || passkeyLoading"
          @click="handlePasskeyLogin"
        >
          <Icon :name="passkeyLoading ? 'loader' : 'fingerprint'" :size="18" />
          {{ passkeyLoading ? "Waiting for your passkey…" : "Sign in with a passkey" }}
        </button>
      </template>
    </form>
  </AuthShell>
</template>
