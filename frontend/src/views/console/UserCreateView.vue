<script setup lang="ts">
import { ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import type { User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { generatePassword } from "../../utils/password";
import FormAlert from "../../components/FormAlert.vue";
import Icon from "../../components/Icon.vue";
import OptionRow from "../../components/OptionRow.vue";
import PasswordInput from "../../components/PasswordInput.vue";
import SegmentedControl from "../../components/SegmentedControl.vue";
import ToggleSwitch from "../../components/ToggleSwitch.vue";

const router = useRouter();
const toast = useToastStore();

const username = ref("");
const displayName = ref("");
const password = ref("");
const role = ref<"admin" | "user">("user");
const active = ref(true);
const calendarScope = ref(false);
const trackerScope = ref(false);
const error = ref("");
const saving = ref(false);
const copied = ref(false);

const roleOptions: { value: "admin" | "user"; label: string }[] = [
  { value: "user", label: "Member" },
  { value: "admin", label: "Admin" },
];

function fillPassword() {
  password.value = generatePassword();
}

async function copyPassword() {
  if (!password.value) return;
  await navigator.clipboard.writeText(password.value);
  copied.value = true;
  toast.success("Password copied");
  setTimeout(() => { copied.value = false; }, 1500);
}

async function create() {
  error.value = "";
  if (!username.value.trim() || !password.value) {
    error.value = "Username and password are required.";
    return;
  }
  saving.value = true;
  try {
    const created = await api.post<User>("/admin/users", {
      username: username.value.trim(),
      display_name: displayName.value.trim() || undefined,
      password: password.value,
      role: role.value,
      active: active.value,
    });
    // Creating takes no scopes, so app access is granted right after.
    if (calendarScope.value || trackerScope.value) {
      try {
        await api.patch<User>(`/admin/users/${created.id}`, { scopes: { calendar: calendarScope.value, tracker: trackerScope.value } });
      } catch (err) {
        toast.error(`User created, but app access wasn't saved: ${err instanceof Error ? err.message : "unknown error"}`);
        router.push({ name: "user-edit", params: { id: created.id } });
        return;
      }
    }
    toast.success(`${created.display_name || created.username} created`);
    router.push({ name: "user-edit", params: { id: created.id } });
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to create user";
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="mx-auto max-w-2xl">
    <RouterLink :to="{ name: 'users' }" class="btn btn-ghost btn-sm -ml-3">
      <Icon name="arrowLeft" :size="14" />
      Users
    </RouterLink>

    <header class="mt-3 mb-6">
      <h1 class="m-0 text-display">New user</h1>
      <p class="m-0 mt-1 text-body text-muted">Share the password with them; they can change it once they sign in.</p>
    </header>

    <form class="flex flex-col gap-5" novalidate @submit.prevent="create">
      <section class="card flex flex-col gap-5 p-5 sm:p-6" aria-labelledby="account-heading">
        <h2 id="account-heading" class="eyebrow m-0">Account</h2>

        <div class="field">
          <label for="new-username">Username</label>
          <input
            id="new-username"
            v-model="username"
            class="input"
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            data-form-type="other"
            data-lpignore="true"
            data-1p-ignore
            data-bwignore="true"
            autofocus
          />
          <p class="field-hint">Stored lowercase; it is the name they sign in with.</p>
        </div>

        <div class="field">
          <label for="new-display-name">Display name</label>
          <input
            id="new-display-name"
            v-model="displayName"
            class="input"
            autocomplete="off"
            spellcheck="false"
            placeholder="Defaults to the username as typed"
          />
          <p class="field-hint">Shown in the apps and in this console.</p>
        </div>

        <div class="field">
          <label for="new-password">Password</label>
          <div class="flex gap-2">
            <PasswordInput
              id="new-password"
              v-model="password"
              class="input font-mono placeholder:font-sans"
              autocomplete="off"
              data-form-type="other"
              data-lpignore="true"
              data-1p-ignore
              data-bwignore="true"
            />
            <button type="button" class="btn btn-secondary h-11 px-3.5" title="Generate a password" @click="fillPassword">
              <Icon name="dice" :size="16" />
              <span class="hidden sm:inline">Generate</span>
            </button>
            <button
              type="button"
              class="btn btn-secondary h-11 w-11 px-0"
              :title="copied ? 'Copied' : 'Copy password'"
              :aria-label="copied ? 'Copied' : 'Copy password'"
              :disabled="!password"
              @click="copyPassword"
            >
              <Icon :name="copied ? 'check' : 'copy'" :size="16" :class="{ 'text-success': copied }" />
            </button>
          </div>
        </div>

        <div class="field">
          <span class="field-label">Role</span>
          <SegmentedControl v-model="role" :options="roleOptions" label="Role" class="w-full sm:w-64" />
          <p class="field-hint">
            {{ role === "admin" ? "Can open this console and manage every account." : "Can sign in to the apps they have access to." }}
          </p>
        </div>
      </section>

      <section class="card divide-y divide-line overflow-hidden" aria-labelledby="access-heading">
        <h2 id="access-heading" class="eyebrow m-0 px-5 pt-5 pb-1 sm:px-6">App access</h2>
        <OptionRow icon="calendar" title="Calendar" description="Legacy Calendar on the web and on phones." class="border-t-0!">
          <ToggleSwitch v-model="calendarScope" aria-label="Calendar access" />
        </OptionRow>
        <OptionRow icon="mapPin" title="Tracker" description="Legacy Tracker on the web and on phones.">
          <ToggleSwitch v-model="trackerScope" aria-label="Tracker access" />
        </OptionRow>
        <OptionRow icon="user" title="Active" description="Disabled accounts can't sign in anywhere.">
          <ToggleSwitch v-model="active" aria-label="Active" />
        </OptionRow>
      </section>

      <FormAlert v-if="error">{{ error }}</FormAlert>

      <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <RouterLink :to="{ name: 'users' }" class="btn btn-secondary">Cancel</RouterLink>
        <button type="submit" class="btn btn-primary" :disabled="saving">
          <Icon :name="saving ? 'loader' : 'userPlus'" :size="16" />
          {{ saving ? "Creating…" : "Create user" }}
        </button>
      </div>
    </form>
  </div>
</template>
