<script setup lang="ts">
import { ref } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useAuthStore } from "../stores/auth";
import { isPasskeySupported } from "../services/webauthn";
import { describePasskeyError, errorMessage } from "../utils/errors";
import { APP_NAME } from "../constants";
import AuthShell from "../components/AuthShell.vue";
import SignInForm from "../components/SignInForm.vue";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const passkeySupported = isPasskeySupported();

const error = ref("");
const loading = ref(false);
const passkeyLoading = ref(false);

const redirect = () => (typeof route.query.redirect === "string" ? route.query.redirect : "/");

async function onSubmit(username: string, password: string) {
  error.value = "";
  loading.value = true;
  try {
    await auth.login(username, password);
    router.push(redirect());
  } catch (err) {
    error.value = errorMessage(err, "Unable to sign in.");
  } finally {
    loading.value = false;
  }
}

async function handlePasskeyLogin(username?: string) {
  error.value = "";
  passkeyLoading.value = true;
  try {
    await auth.loginWithPasskey(username);
    router.push(redirect());
  } catch (err) {
    error.value = describePasskeyError(err, "Passkey sign-in failed.");
  } finally {
    passkeyLoading.value = false;
  }
}
</script>

<template>
  <AuthShell :title="APP_NAME">
    <template #subtitle>
      <p class="m-0 mt-1.5 text-body text-muted">Sign in to manage your Legacy account.</p>
    </template>

    <SignInForm
      :passkey-supported="passkeySupported"
      :loading="loading"
      :passkey-loading="passkeyLoading"
      :error="error"
      @invalid="error = 'Enter your username and password.'"
      @submit="onSubmit"
      @passkey="handlePasskeyLogin"
    />
  </AuthShell>
</template>
