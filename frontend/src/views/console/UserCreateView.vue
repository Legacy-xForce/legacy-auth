<script setup lang="ts">
import { ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import type { User } from "../../stores/auth";
import Icon from "../../components/Icon.vue";
import ToggleSwitch from "../../components/ToggleSwitch.vue";
import PasswordInput from "../../components/PasswordInput.vue";

const router = useRouter();

const username = ref("");
const password = ref("");
const role = ref<"admin" | "user">("user");
const active = ref(true);
const error = ref("");
const saving = ref(false);

function generatePassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";
  password.value = Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
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
      password: password.value,
      role: role.value,
      active: active.value,
    });
    router.push({ name: "user-edit", params: { id: created.id } });
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to create user";
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div>
    <div class="mb-4 flex gap-1.5 text-sm text-text-dim">
      <RouterLink :to="{ name: 'users' }" class="text-text-muted no-underline hover:text-text">Users</RouterLink>
      <span>/</span>
      <span>Add New User</span>
    </div>

    <div class="mb-6 flex flex-col items-start gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 class="m-0 mb-1 text-2xl font-bold">Add New User</h1>
        <p class="m-0 text-sm text-text-muted">Create a new authentication identity.</p>
      </div>
      <div class="flex w-full gap-2.5 sm:w-auto">
        <RouterLink :to="{ name: 'users' }" class="btn btn-ghost flex-1 sm:flex-none">Cancel</RouterLink>
        <button class="btn btn-primary flex-1 sm:flex-none" :disabled="saving" @click="create">
          {{ saving ? "Creating…" : "Create User" }}
        </button>
      </div>
    </div>

    <p v-if="error" class="text-sm text-danger">{{ error }}</p>

    <div class="card max-w-120 p-6">
      <div class="field mb-4">
        <label>Username</label>
        <input v-model="username" class="input" autocomplete="off" />
      </div>
      <div class="field mb-4">
        <label>Password</label>
        <div class="flex flex-col gap-2.5 sm:flex-row">
          <PasswordInput v-model="password" class="input" autocomplete="new-password" />
          <button type="button" class="btn btn-ghost shrink-0" @click="generatePassword">
            <Icon name="key" :size="14" />
            Generate
          </button>
        </div>
      </div>
      <div class="field mb-4">
        <label>Role</label>
        <select v-model="role" class="input">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <div class="flex items-center justify-between border-t border-border pt-3.5">
        <div class="text-[0.88rem] font-semibold">Active</div>
        <ToggleSwitch v-model="active" />
      </div>
    </div>
  </div>
</template>
