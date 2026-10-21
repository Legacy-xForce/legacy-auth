<script setup lang="ts">
import { onMounted, ref } from "vue";
import { getPasskeyAssertion, isPasskeySupported } from "../services/webauthn";
import Icon from "../components/Icon.vue";
import PasswordInput from "../components/PasswordInput.vue";

// The sign-in page of the OpenID Provider: an app sent the browser here (via /authorize) and
// the user has to prove who they are. It talks only to this page's own /interaction/:uid API,
// with the interaction cookie the browser already holds — never with the console's tokens.

const props = defineProps<{ uid: string }>();

type Details = {
  uid: string;
  prompt: string;
  client: { id: string | null; name: string | null };
  login_hint: string | null;
  /** Set when prompt is "no_access": the signed-in account may not use this app. */
  reason?: "disabled" | "admin" | "no_scope" | "unknown_resource";
  username?: string | null;
};

class InteractionError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const passkeySupported = isPasskeySupported();

const details = ref<Details | null>(null);
const expired = ref(false);
const username = ref("");
const password = ref("");
const error = ref("");
const loading = ref(false);
const passkeyLoading = ref(false);
const cancelling = ref(false);
const switching = ref(false);

/** A JSON call to this interaction. Same-origin, so the browser sends the interaction cookie and the Origin header the server checks. */
async function call<T>(action: string, options: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "POST";
  const response = await fetch(`/interaction/${encodeURIComponent(props.uid)}/${action}`, {
    method,
    credentials: "same-origin",
    headers: method === "POST" ? { "Content-Type": "application/json" } : undefined,
    body: method === "POST" ? JSON.stringify(options.body ?? {}) : undefined,
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new InteractionError(data?.error ?? response.statusText, response.status);
  return data as T;
}

/** Continues to the URL the server returned, but only if it stays on this origin: the server only ever sends us to its own /authorize. */
function proceed(redirect: string) {
  const target = new URL(redirect, window.location.href);
  if (target.origin !== window.location.origin) {
    error.value = "Unexpected redirect; sign-in stopped.";
    return;
  }
  window.location.assign(target.toString());
}

function explain(failure: unknown, fallback: string): string {
  if (failure instanceof InteractionError) {
    if (failure.status === 410) expired.value = true;
    return failure.message;
  }
  return fallback;
}

onMounted(async () => {
  try {
    details.value = await call<Details>("details", { method: "GET" });
    username.value = details.value.login_hint ?? "";
  } catch (failure) {
    if (failure instanceof InteractionError && failure.status === 410) expired.value = true;
    else error.value = explain(failure, "Unable to load the sign-in page.");
  }
});

async function onSubmit() {
  error.value = "";
  if (!username.value.trim() || !password.value) {
    error.value = "Enter your username and password.";
    return;
  }
  loading.value = true;
  try {
    const result = await call<{ redirect: string }>("login", { body: { username: username.value.trim(), password: password.value } });
    proceed(result.redirect);
  } catch (failure) {
    error.value = explain(failure, "Unable to sign in.");
  } finally {
    loading.value = false;
  }
}

async function onPasskey() {
  error.value = "";
  passkeyLoading.value = true;
  try {
    const options = await call<any>("passkey/options", { body: { username: username.value.trim() || undefined } });
    const assertion = await getPasskeyAssertion(options);
    const result = await call<{ redirect: string }>("passkey/verify", { body: assertion });
    proceed(result.redirect);
  } catch (failure: any) {
    error.value =
      failure?.name === "NotAllowedError" ? "Passkey authentication was cancelled or timed out." : explain(failure, failure?.message || "Passkey sign-in failed.");
  } finally {
    passkeyLoading.value = false;
  }
}

async function onSwitchAccount() {
  error.value = "";
  switching.value = true;
  try {
    const result = await call<{ redirect: string }>("switch-account");
    proceed(result.redirect);
  } catch (failure) {
    error.value = explain(failure, "Unable to switch account.");
    switching.value = false;
  }
}

async function onCancel() {
  cancelling.value = true;
  try {
    const result = await call<{ redirect: string }>("abort");
    proceed(result.redirect);
  } catch (failure) {
    error.value = explain(failure, "Unable to cancel.");
    cancelling.value = false;
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col items-center px-6 pb-16 pt-12">
    <div class="mb-7 text-center">
      <div class="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-accent-soft text-accent">
        <Icon name="shield" :size="22" />
      </div>
      <h1 class="m-0 text-2xl font-bold">Legacy</h1>
      <p v-if="details?.prompt === 'no_access'" class="mt-1 text-sm text-text-muted" data-testid="client-name">
        Access denied
      </p>
      <p v-else-if="details?.client.name" class="mt-1 text-sm text-text-muted" data-testid="client-name">
        Sign in to <strong class="font-semibold text-text">{{ details.client.name }}</strong>
      </p>
      <p v-else class="mt-1 text-sm text-text-muted">Sign in with your Legacy account</p>
    </div>

    <div v-if="expired" class="card flex w-full max-w-95 flex-col gap-3 p-7" data-testid="expired">
      <h2 class="m-0 text-base font-semibold">This sign-in link has expired</h2>
      <p class="m-0 text-sm text-text-muted">Go back to the app you came from and start signing in again.</p>
    </div>

    <div v-else-if="details?.prompt === 'no_access'" class="card flex w-full max-w-95 flex-col gap-4 p-7" data-testid="no-access">
      <template v-if="details.reason === 'disabled'">
        <h2 class="m-0 text-base font-semibold">This account is turned off</h2>
        <p class="m-0 text-sm text-text-muted">Ask an administrator to turn it back on, or sign in with another account.</p>
      </template>
      <template v-else>
        <h2 class="m-0 text-base font-semibold">No access to {{ details.client.name ?? "this app" }}</h2>
        <p class="m-0 text-sm text-text-muted">
          <template v-if="details.username">
            You are signed in as <strong class="font-semibold text-text">{{ details.username }}</strong>, which has no access to
            {{ details.client.name ?? "this app" }}.
          </template>
          <template v-else>Your account has no access to {{ details.client.name ?? "this app" }}.</template>
          Ask an administrator for access, or sign in with another account.
        </p>
      </template>

      <p v-if="error" class="m-0 text-[0.82rem] text-danger" role="alert" data-testid="error">{{ error }}</p>

      <button type="button" class="btn btn-primary w-full py-3 text-[0.95rem]" :disabled="switching || cancelling" data-testid="switch-account" @click="onSwitchAccount">
        <Icon name="user" :size="16" />
        {{ switching ? "Redirecting…" : "Use another account" }}
      </button>
      <button type="button" class="btn btn-ghost w-full text-[0.85rem]" :disabled="switching || cancelling" data-testid="back" @click="onCancel">
        Back to {{ details.client.name ?? "the app" }}
      </button>
    </div>

    <form v-else class="card flex w-full max-w-95 flex-col gap-4.5 p-7" @submit.prevent="onSubmit">
      <div class="field">
        <label for="username">Username</label>
        <div class="input-wrap">
          <Icon name="mail" />
          <input id="username" v-model="username" class="input" placeholder="username" autocomplete="username webauthn" autofocus />
        </div>
      </div>

      <div class="field">
        <label for="password">Password</label>
        <div class="input-wrap">
          <Icon name="lock" />
          <PasswordInput id="password" v-model="password" class="input" placeholder="••••••••" autocomplete="current-password" />
        </div>
      </div>

      <p v-if="error" class="m-0 text-[0.82rem] text-danger" role="alert" data-testid="error">{{ error }}</p>

      <button type="submit" class="btn btn-primary w-full py-3 text-[0.95rem]" :disabled="loading || passkeyLoading || cancelling">
        {{ loading ? "Signing in…" : "Sign In" }}
        <Icon name="arrowRight" :size="16" />
      </button>

      <template v-if="passkeySupported">
        <div class="relative my-0.5 flex items-center justify-center">
          <div class="w-full border-t border-border"></div>
          <span class="absolute bg-bg-card px-2.5 text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">or</span>
        </div>

        <button type="button" class="btn btn-ghost w-full py-3 text-[0.95rem]" :disabled="loading || passkeyLoading || cancelling" @click="onPasskey">
          <Icon name="key" :size="16" />
          {{ passkeyLoading ? "Authenticating…" : "Sign in with Passkey" }}
        </button>
      </template>

      <button type="button" class="btn btn-ghost w-full text-[0.85rem]" :disabled="loading || passkeyLoading || cancelling" data-testid="cancel" @click="onCancel">
        Cancel
      </button>
    </form>
  </div>
</template>
