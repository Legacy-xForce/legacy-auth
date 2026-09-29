<script setup lang="ts">
import { ref } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useAuthStore } from "../stores/auth";
import { ApiError } from "../api/client";
import { isPasskeySupported } from "../services/webauthn";
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
  <div class="flex min-h-screen flex-col items-center px-6 pb-16 pt-12">
    <div class="mb-7 text-center">
      <div class="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-accent-soft text-accent">
        <Icon name="shield" :size="22" />
      </div>
      <h1 class="m-0 text-2xl font-bold">Legacy Auth</h1>
      <p class="mt-1 text-sm text-text-muted">Management Console Access</p>
    </div>

    <form class="card flex w-full max-w-95 flex-col gap-4.5 p-7" @submit.prevent="onSubmit">
      <div class="field">
        <label for="username">Username</label>
        <div class="input-wrap">
          <Icon name="mail" />
          <input id="username" v-model="username" class="input" placeholder="username" autocomplete="username" />
        </div>
      </div>

      <div class="field">
        <div class="flex items-center justify-between">
          <label for="password">Password</label>
        </div>
        <div class="input-wrap">
          <Icon name="lock" />
          <PasswordInput
            id="password"
            v-model="password"
            class="input"
            placeholder="••••••••"
            autocomplete="current-password"
          />
        </div>
      </div>

      <p v-if="error" class="m-0 text-[0.82rem] text-danger">{{ error }}</p>

      <button type="submit" class="btn btn-primary w-full py-3 text-[0.95rem]" :disabled="loading || passkeyLoading">
        {{ loading ? "Signing in…" : "Sign In" }}
        <Icon name="arrowRight" :size="16" />
      </button>

      <template v-if="passkeySupported">
        <div class="relative my-0.5 flex items-center justify-center">
          <div class="w-full border-t border-border"></div>
          <span class="absolute bg-bg-card px-2.5 text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">or</span>
        </div>

        <button
          type="button"
          class="btn btn-ghost w-full py-3 text-[0.95rem]"
          :disabled="loading || passkeyLoading"
          @click="handlePasskeyLogin"
        >
          <Icon name="key" :size="16" />
          {{ passkeyLoading ? "Authenticating…" : "Sign in with Passkey" }}
        </button>
      </template>
    </form>
  </div>
</template>
