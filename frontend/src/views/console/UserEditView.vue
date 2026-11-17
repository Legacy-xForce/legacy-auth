<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import { useAuthStore, type User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { errorMessage } from "../../utils/errors";
import type { Role } from "../../constants";
import AppAccessSection from "../../components/AppAccessSection.vue";
import AvatarUpload from "../../components/AvatarUpload.vue";
import ConfirmDialog from "../../components/ConfirmDialog.vue";
import EmptyState from "../../components/EmptyState.vue";
import FormAlert from "../../components/FormAlert.vue";
import Icon from "../../components/Icon.vue";
import PasswordField from "../../components/PasswordField.vue";
import RoleChip from "../../components/RoleChip.vue";
import SkeletonRow from "../../components/SkeletonRow.vue";
import StatusPill from "../../components/StatusPill.vue";
import UserIdentityFields from "../../components/UserIdentityFields.vue";

const props = defineProps<{ id: string }>();
const router = useRouter();
const authStore = useAuthStore();
const toast = useToastStore();

const user = ref<User | null>(null);
const loadError = ref("");
const username = ref("");
const displayName = ref("");
const role = ref<Role>("user");
const active = ref(true);
const calendarScope = ref(false);
const trackerScope = ref(false);
const password = ref("");

const saving = ref(false);
const deleting = ref(false);
const confirmingDelete = ref(false);
const error = ref("");

const isSelf = computed(() => user.value?.id === authStore.user?.id);

const dirty = computed(() => {
  const u = user.value;
  if (!u) return false;
  return (
    username.value.trim() !== u.username ||
    displayName.value.trim() !== u.display_name ||
    role.value !== u.role ||
    active.value !== u.active ||
    calendarScope.value !== u.scopes.calendar ||
    trackerScope.value !== u.scopes.tracker ||
    password.value !== ""
  );
});

function applyUser(u: User) {
  user.value = u;
  username.value = u.username;
  displayName.value = u.display_name;
  role.value = u.role;
  active.value = u.active;
  calendarScope.value = u.scopes.calendar;
  trackerScope.value = u.scopes.tracker;
}

async function load() {
  try {
    const u = await api.get<User>(`/admin/users/${props.id}`);
    applyUser(u);
  } catch (err) {
    loadError.value = errorMessage(err, "Couldn't load this user");
  }
}

onMounted(load);

async function save() {
  error.value = "";
  saving.value = true;
  try {
    const payload: Record<string, unknown> = {
      username: username.value.trim(),
      display_name: displayName.value.trim(),
      role: role.value,
      active: active.value,
      scopes: { calendar: calendarScope.value, tracker: trackerScope.value },
    };
    if (password.value) payload.password = password.value;
    const updated = await api.patch<User>(`/admin/users/${props.id}`, payload);
    applyUser(updated);
    password.value = "";
    toast.success("Changes saved");
  } catch (err) {
    error.value = errorMessage(err, "Failed to save changes");
  } finally {
    saving.value = false;
  }
}

function discard() {
  if (user.value) applyUser(user.value);
  password.value = "";
  error.value = "";
}

async function confirmDelete() {
  error.value = "";
  deleting.value = true;
  try {
    await api.delete(`/admin/users/${props.id}`);
    toast.success(`${user.value?.display_name || user.value?.username || "User"} deleted`);
    router.push({ name: "users" });
  } catch (err) {
    error.value = errorMessage(err, "Failed to delete user");
    confirmingDelete.value = false;
  } finally {
    deleting.value = false;
  }
}
</script>

<template>
  <div class="mx-auto max-w-2xl" :class="{ 'pb-24': dirty }">
    <RouterLink :to="{ name: 'users' }" class="btn btn-ghost btn-sm -ml-3">
      <Icon name="arrowLeft" :size="14" />
      Users
    </RouterLink>

    <div v-if="loadError" class="card mt-4">
      <EmptyState icon="user" heading="h1" title="This user couldn't be loaded" :description="loadError" />
    </div>

    <SkeletonRow v-else-if="!user" :size="72" class="mt-4" />

    <template v-else>
      <header class="mt-3 mb-6 flex items-center gap-4">
        <AvatarUpload
          :user-id="user.id"
          :name="user.display_name || user.username"
          :endpoint="`/admin/users/${user.id}/avatar`"
        />
        <div class="min-w-0">
          <h1 class="m-0 truncate text-display">{{ user.display_name || user.username }}</h1>
          <p class="m-0 mt-0.5 truncate text-meta text-subtle">@{{ user.username }}</p>
          <div class="mt-1.5 flex flex-wrap items-center gap-2">
            <RoleChip :role="user.role" />
            <StatusPill :active="user.active" />
            <span v-if="isSelf" class="chip bg-fg/6 text-muted">You</span>
          </div>
        </div>
      </header>

      <form class="flex flex-col gap-5" novalidate @submit.prevent="save">
        <UserIdentityFields
          id-prefix="edit"
          heading-id="identity-heading"
          v-model:username="username"
          v-model:display-name="displayName"
          v-model:role="role"
        >
          <div class="field">
            <label for="edit-password">New password</label>
            <PasswordField id="edit-password" v-model="password" placeholder="Unchanged" autocomplete="new-password" />
          </div>

          <div class="flex items-center justify-between gap-3 border-t border-line pt-4">
            <span class="field-label shrink-0">User ID</span>
            <span class="truncate font-mono text-xs text-subtle select-all">{{ user.id }}</span>
          </div>
        </UserIdentityFields>

        <AppAccessSection
          v-model:calendar="calendarScope"
          v-model:tracker="trackerScope"
          v-model:active="active"
          :active-description="active ? 'This account can sign in.' : 'Disabled: this account can\'t sign in anywhere.'"
        />

        <FormAlert v-if="error">{{ error }}</FormAlert>

        <section v-if="!isSelf" class="card border-danger/25 p-5 sm:p-6" aria-labelledby="danger-heading">
          <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 id="danger-heading" class="m-0 text-title">Delete this user</h2>
              <p class="m-0 mt-0.5 text-meta text-muted">Removes the account and signs it out of every app. This can't be undone.</p>
            </div>
            <button type="button" class="btn btn-danger" :disabled="deleting" @click="confirmingDelete = true">
              <Icon name="trash" :size="16" />
              Delete user
            </button>
          </div>
        </section>

        <Transition name="savebar">
          <div
            v-if="dirty"
            class="fixed inset-x-3 bottom-[max(0.75rem,env(safe-area-inset-bottom))] z-20 mx-auto flex max-w-2xl items-center gap-2 rounded-2xl border border-line bg-overlay/95 py-2.5 pr-2.5 pl-4 shadow-(--shadow-overlay) backdrop-blur-xl sm:inset-x-6"
          >
            <span class="flex-1 text-meta font-medium text-muted">Unsaved changes</span>
            <button type="button" class="btn btn-ghost" :disabled="saving" @click="discard">Discard</button>
            <button type="submit" class="btn btn-primary" :disabled="saving">
              <Icon v-if="saving" name="loader" :size="16" />
              {{ saving ? "Saving…" : "Save changes" }}
            </button>
          </div>
        </Transition>
      </form>

      <ConfirmDialog
        :open="confirmingDelete"
        :title="`Delete ${user.display_name || user.username}?`"
        message="The account is removed and signed out of every Legacy app. This can't be undone."
        confirm-label="Delete user"
        danger
        :busy="deleting"
        @confirm="confirmDelete"
        @cancel="confirmingDelete = false"
      />
    </template>
  </div>
</template>
