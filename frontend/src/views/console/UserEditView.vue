<script setup lang="ts">
import { onMounted, ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import { useAuthStore, type User } from "../../stores/auth";
import Icon from "../../components/Icon.vue";
import ToggleSwitch from "../../components/ToggleSwitch.vue";
import UserAvatar from "../../components/UserAvatar.vue";
import PasswordInput from "../../components/PasswordInput.vue";
import ConfirmDialog from "../../components/ConfirmDialog.vue";

const props = defineProps<{ id: string }>();
const router = useRouter();
const authStore = useAuthStore();

const user = ref<User | null>(null);
const username = ref("");
const role = ref<"admin" | "user">("user");
const active = ref(true);
const calendarScope = ref(false);
const trackerScope = ref(false);
const password = ref("");

const saving = ref(false);
const deleting = ref(false);
const confirmingDelete = ref(false);
const error = ref("");
const avatarInput = ref<HTMLInputElement | null>(null);
const avatarVersion = ref(0);

function applyUser(u: User) {
  user.value = u;
  username.value = u.username;
  role.value = u.role;
  active.value = u.active;
  calendarScope.value = u.scopes.calendar;
  trackerScope.value = u.scopes.tracker;
}

async function load() {
  const u = await api.get<User>(`/admin/users/${props.id}`);
  applyUser(u);
}

onMounted(load);

function generatePassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";
  password.value = Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}

function triggerAvatarUpload() {
  avatarInput.value?.click();
}

async function onAvatarSelected(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);
  try {
    await api.postForm(`/admin/users/${props.id}/avatar`, formData);
    avatarVersion.value++;
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to upload avatar";
  } finally {
    (event.target as HTMLInputElement).value = "";
  }
}

async function save() {
  error.value = "";
  saving.value = true;
  try {
    const payload: Record<string, unknown> = {
      username: username.value.trim(),
      role: role.value,
      active: active.value,
      scopes: { calendar: calendarScope.value, tracker: trackerScope.value },
    };
    if (password.value) {
      payload.password = password.value;
    }
    const updated = await api.patch<User>(`/admin/users/${props.id}`, payload);
    applyUser(updated);
    password.value = "";
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to save changes";
  } finally {
    saving.value = false;
  }
}

function discard() {
  router.push({ name: "users" });
}

async function confirmDelete() {
  error.value = "";
  deleting.value = true;
  try {
    await api.delete(`/admin/users/${props.id}`);
    router.push({ name: "users" });
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to delete user";
    confirmingDelete.value = false;
  } finally {
    deleting.value = false;
  }
}
</script>

<template>
  <div v-if="user">
    <div class="mb-4 flex gap-1.5 text-sm text-text-dim">
      <RouterLink :to="{ name: 'users' }" class="text-text-muted no-underline hover:text-text">Users</RouterLink>
      <span>/</span>
      <span>Edit User</span>
    </div>

    <div class="mb-6 flex flex-col items-start gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 class="m-0 mb-1 text-2xl font-bold">Edit Identity</h1>
        <p class="m-0 text-sm text-text-muted">Modify access scopes, credentials, and profile configuration.</p>
      </div>
      <div class="flex w-full shrink-0 flex-wrap gap-2.5 sm:w-auto sm:flex-nowrap">
        <button
          v-if="user.id !== authStore.user?.id"
          class="btn btn-danger flex-1 sm:flex-none"
          :disabled="deleting"
          @click="confirmingDelete = true"
        >
          <Icon name="trash" :size="14" />
          {{ deleting ? "Deleting…" : "Delete User" }}
        </button>
        <button class="btn btn-ghost flex-1 sm:flex-none" @click="discard">Discard</button>
        <button class="btn btn-primary flex-1 sm:flex-none" :disabled="saving" @click="save">
          {{ saving ? "Saving…" : "Save Changes" }}
        </button>
      </div>
    </div>

    <p v-if="error" class="text-sm text-danger">{{ error }}</p>

    <div class="grid grid-cols-[260px_1fr] items-start gap-5 max-[720px]:grid-cols-1">
      <div class="card flex flex-col items-center p-7 py-7 text-center">
        <button class="relative rounded-full border-none bg-none p-0" @click="triggerAvatarUpload">
          <UserAvatar :key="avatarVersion" :user-id="user.id" :size="96" />
          <span class="absolute bottom-0.5 right-0.5 flex h-6.5 w-6.5 items-center justify-center rounded-full border-2 border-bg-card bg-accent text-white">
            <Icon name="pencil" :size="14" />
          </span>
        </button>
        <input ref="avatarInput" type="file" accept="image/*" class="hidden" @change="onAvatarSelected" />
        <div class="mt-3.5 font-bold">{{ user.username }}</div>
        <span
          class="mt-2 rounded-full px-2.5 py-1 text-xs"
          :class="active ? 'bg-success-soft text-success' : 'bg-bg-input text-text-dim'"
        >
          {{ active ? "Active Account" : "Inactive Account" }}
        </span>
      </div>

      <div class="flex flex-col gap-5">
        <div class="card p-6">
          <h3 class="m-0 mb-4 text-base">Identity Information</h3>

          <div class="field mb-4">
            <label>Username</label>
            <input v-model="username" class="input" />
          </div>

          <div class="field mb-4">
            <label>Password</label>
            <div class="flex flex-col gap-2.5 sm:flex-row">
              <PasswordInput v-model="password" class="input" placeholder="Leave blank to keep current password" />
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

          <div class="mt-2 flex items-center justify-between gap-4 border-t border-border pt-3.5">
            <div>
              <div class="text-[0.88rem] font-semibold">Account Status</div>
              <div class="mt-0.5 max-w-80 text-xs text-text-dim">Enable or disable this user's access to the system.</div>
            </div>
            <div class="flex shrink-0 items-center gap-2.5 text-[0.82rem] text-text-muted">
              <span>{{ active ? "Active" : "Inactive" }}</span>
              <ToggleSwitch v-model="active" />
            </div>
          </div>
        </div>

        <div class="card p-6">
          <h3 class="m-0 mb-4 text-base">Application Scopes</h3>
          <p class="-mt-2 mb-4 text-[0.82rem] text-text-dim">Manage which internal applications and APIs this user can access.</p>

          <div class="flex items-center justify-between gap-4 py-3.5">
            <div class="flex items-center gap-3">
              <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-ui bg-bg-input text-text-muted">
                <Icon name="calendar" :size="18" />
              </div>
              <div>
                <div class="text-[0.88rem] font-semibold">Calendar</div>
                <div class="mt-0.5 max-w-80 text-xs text-text-dim">Enables access to the Legacy Calendar application</div>
              </div>
            </div>
            <ToggleSwitch v-model="calendarScope" />
          </div>

          <div class="flex items-center justify-between gap-4 border-t border-border py-3.5">
            <div class="flex items-center gap-3">
              <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-ui bg-bg-input text-text-muted">
                <Icon name="chart" :size="18" />
              </div>
              <div>
                <div class="text-[0.88rem] font-semibold">Tracker</div>
                <div class="mt-0.5 max-w-80 text-xs text-text-dim">Enables access to the Legacy Tracker application</div>
              </div>
            </div>
            <ToggleSwitch v-model="trackerScope" />
          </div>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :open="confirmingDelete"
      title="Delete this user?"
      :message="`Permanently delete “${user.username}”. This action cannot be undone.`"
      confirm-label="Delete User"
      danger
      :busy="deleting"
      @confirm="confirmDelete"
      @cancel="confirmingDelete = false"
    />
  </div>
</template>
