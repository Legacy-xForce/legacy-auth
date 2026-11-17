<script setup lang="ts">
import { ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import type { User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { errorMessage, missingFields } from "../../utils/errors";
import type { Role } from "../../constants";
import AppAccessSection from "../../components/AppAccessSection.vue";
import FormAlert from "../../components/FormAlert.vue";
import Icon from "../../components/Icon.vue";
import PasswordField from "../../components/PasswordField.vue";
import UserIdentityFields from "../../components/UserIdentityFields.vue";

const router = useRouter();
const toast = useToastStore();

const username = ref("");
const displayName = ref("");
const password = ref("");
const role = ref<Role>("user");
const active = ref(true);
const calendarScope = ref(false);
const trackerScope = ref(false);
const error = ref("");
const saving = ref(false);

async function create() {
  error.value = "";
  if (missingFields(username.value, password.value)) {
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
        toast.error(`User created, but app access wasn't saved: ${errorMessage(err, "unknown error")}`);
        router.push({ name: "user-edit", params: { id: created.id } });
        return;
      }
    }
    toast.success(`${created.display_name || created.username} created`);
    router.push({ name: "user-edit", params: { id: created.id } });
  } catch (err) {
    error.value = errorMessage(err, "Failed to create user");
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
      <UserIdentityFields
        id-prefix="new"
        heading-id="account-heading"
        v-model:username="username"
        v-model:display-name="displayName"
        v-model:role="role"
      >
        <div class="field">
          <label for="new-password">Password</label>
          <PasswordField id="new-password" v-model="password" />
        </div>
      </UserIdentityFields>

      <AppAccessSection
        v-model:calendar="calendarScope"
        v-model:tracker="trackerScope"
        v-model:active="active"
      />

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
