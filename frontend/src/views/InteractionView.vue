<script setup lang="ts">
import { onMounted, ref } from "vue";
import { getPasskeyAssertion, isPasskeySupported } from "../services/webauthn";
import AuthShell from "../components/AuthShell.vue";
import FormAlert from "../components/FormAlert.vue";
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
  <AuthShell :title="expired ? 'Link expired' : 'Sign in'">
    <template #subtitle>
      <p v-if="expired" class="m-0 mt-1.5 text-body text-muted">This sign-in page is no longer valid.</p>
      <p v-else-if="details?.client.name" class="m-0 mt-1.5 text-body text-muted" data-testid="client-name">
        to continue to <strong class="font-semibold text-fg">{{ details.client.name }}</strong>
      </p>
      <p v-else class="m-0 mt-1.5 text-body text-muted">with your Legacy account</p>
    </template>

    <div v-if="expired" class="card flex flex-col items-center gap-4 p-7 text-center" data-testid="expired">
      <div class="flex size-12 items-center justify-center rounded-full bg-warning/12 text-warning">
        <Icon name="alertTriangle" :size="22" />
      </div>
      <div>
        <h2 class="m-0 text-title">This sign-in link has expired</h2>
        <p class="m-0 mt-1.5 text-body text-muted">Go back to the app you came from and start signing in again.</p>
      </div>
    </div>

    <template v-else>
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
              autocomplete="username webauthn"
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
            <PasswordInput id="password" v-model="password" class="input" placeholder="Your password" autocomplete="current-password" />
          </div>
        </div>

        <FormAlert v-if="error" data-testid="error">{{ error }}</FormAlert>

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

          <button type="button" class="btn btn-secondary btn-lg w-full" :disabled="loading || passkeyLoading || cancelling" @click="onPasskey">
            <Icon :name="passkeyLoading ? 'loader' : 'fingerprint'" :size="18" />
            {{ passkeyLoading ? "Waiting for your passkey…" : "Sign in with a passkey" }}
          </button>
        </template>
      </form>

      <div class="mt-5 flex justify-center">
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          :disabled="loading || passkeyLoading || cancelling"
          data-testid="cancel"
          @click="onCancel"
        >
          <Icon :name="cancelling ? 'loader' : 'arrowLeft'" :size="14" />
          {{ details?.client.name ? `Back to ${details.client.name}` : "Cancel" }}
        </button>
      </div>
    </template>
  </AuthShell>
</template>
