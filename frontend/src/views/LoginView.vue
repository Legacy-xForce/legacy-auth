<script setup lang="ts">
import { ref } from "vue";
import { useRouter, useRoute } from "vue-router";
import { useAuthStore } from "../stores/auth";
import { ApiError } from "../api/client";
import Icon from "../components/Icon.vue";
import PasswordInput from "../components/PasswordInput.vue";

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const username = ref("");
const password = ref("");
const error = ref("");
const loading = ref(false);

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

const previewActions = [
  { icon: "key", title: "Reset Password", desc: "Enforce new security credentials" },
  { icon: "user", title: "Update Avatar", desc: "Change profile picture" },
  { icon: "briefcase", title: "Change Username", desc: "Modify system handle" },
];
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
          <a href="#" class="text-sm text-accent no-underline">Forgot?</a>
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

      <button type="submit" class="btn btn-primary w-full py-3 text-[0.95rem]" :disabled="loading">
        {{ loading ? "Signing in…" : "Sign In" }}
        <Icon name="arrowRight" :size="16" />
      </button>
    </form>

    <div class="my-10 flex w-full max-w-160 items-center gap-4 text-[0.72rem] uppercase tracking-wider text-text-dim">
      <span class="h-px flex-1 bg-border" />
      <span>Console Preview</span>
      <span class="h-px flex-1 bg-border" />
    </div>

    <div class="w-full max-w-160 text-center">
      <h2 class="m-0 text-lg font-bold">Quick Profile Actions</h2>
      <p class="mb-6 mt-1.5 text-sm text-text-muted">Available immediately upon authentication</p>
      <div class="grid grid-cols-3 gap-4 max-[560px]:grid-cols-1">
        <div v-for="action in previewActions" :key="action.title" class="card p-5 text-center">
          <div class="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-bg-input text-text-muted">
            <Icon :name="action.icon" :size="20" />
          </div>
          <div class="text-sm font-semibold">{{ action.title }}</div>
          <div class="mt-1 text-xs text-text-dim">{{ action.desc }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
