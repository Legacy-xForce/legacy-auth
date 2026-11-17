<script setup lang="ts">
import { onMounted, ref } from "vue";
import { fetchJson } from "../api/client";
import { getPasskeyAssertion, isPasskeySupported } from "../services/webauthn";
import { describePasskeyError } from "../utils/errors";
import AuthShell from "../components/AuthShell.vue";
import EmptyState from "../components/EmptyState.vue";
import Icon from "../components/Icon.vue";
import SignInForm from "../components/SignInForm.vue";

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
const error = ref("");
const loading = ref(false);
const passkeyLoading = ref(false);
const cancelling = ref(false);

/** A JSON call to this interaction. Same-origin, so the browser sends the interaction cookie and the Origin header the server checks. */
function call<T>(action: string, options: { method?: "GET" | "POST"; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "POST";
  return fetchJson<T>(
    `/interaction/${encodeURIComponent(props.uid)}/${action}`,
    {
      method,
      credentials: "same-origin",
      headers: method === "POST" ? { "Content-Type": "application/json" } : undefined,
      body: method === "POST" ? JSON.stringify(options.body ?? {}) : undefined,
    },
    InteractionError
  );
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
  } catch (failure) {
    if (failure instanceof InteractionError && failure.status === 410) expired.value = true;
    else error.value = explain(failure, "Unable to load the sign-in page.");
  }
});

async function onSubmit(username: string, password: string) {
  error.value = "";
  loading.value = true;
  try {
    const result = await call<{ redirect: string }>("login", { body: { username, password } });
    proceed(result.redirect);
  } catch (failure) {
    error.value = explain(failure, "Unable to sign in.");
  } finally {
    loading.value = false;
  }
}

async function onPasskey(hint?: string) {
  error.value = "";
  passkeyLoading.value = true;
  try {
    const options = await call<any>("passkey/options", { body: { username: hint } });
    const assertion = await getPasskeyAssertion(options);
    const result = await call<{ redirect: string }>("passkey/verify", { body: assertion });
    proceed(result.redirect);
  } catch (failure: any) {
    if (failure instanceof InteractionError && failure.status === 410) expired.value = true;
    error.value = describePasskeyError(failure, failure?.message || "Passkey sign-in failed.");
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

    <EmptyState
      v-if="expired"
      icon="alertTriangle"
      heading="h2"
      title="This sign-in link has expired"
      description="Go back to the app you came from and start signing in again."
      tone="warning"
      surface
      data-testid="expired"
    />

    <template v-else>
      <SignInForm
        :passkey-supported="passkeySupported"
        :loading="loading"
        :passkey-loading="passkeyLoading"
        :cancelling="cancelling"
        :error="error"
        :initial-username="details?.login_hint ?? ''"
        username-autocomplete="username webauthn"
        :error-test-id="true"
        @invalid="error = 'Enter your username and password.'"
        @submit="onSubmit"
        @passkey="onPasskey"
      />

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
