<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { api } from "../../api/client";
import { useAuthStore, type User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { generatePassword } from "../../utils/password";
import ConfirmDialog from "../../components/ConfirmDialog.vue";
import FormAlert from "../../components/FormAlert.vue";
import Icon from "../../components/Icon.vue";
import OptionRow from "../../components/OptionRow.vue";
import PasswordInput from "../../components/PasswordInput.vue";
import SegmentedControl from "../../components/SegmentedControl.vue";
import StatusPill from "../../components/StatusPill.vue";
import ToggleSwitch from "../../components/ToggleSwitch.vue";
import UserAvatar from "../../components/UserAvatar.vue";

const props = defineProps<{ id: string }>();
const router = useRouter();
const authStore = useAuthStore();
const toast = useToastStore();

const user = ref<User | null>(null);
const loadError = ref("");
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

const roleOptions: { value: "admin" | "user"; label: string }[] = [
  { value: "user", label: "Member" },
  { value: "admin", label: "Admin" },
];

const isSelf = computed(() => user.value?.id === authStore.user?.id);

const dirty = computed(() => {
  const u = user.value;
  if (!u) return false;
  return (
    username.value.trim() !== u.username ||
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
    loadError.value = err instanceof Error ? err.message : "Couldn't load this user";
  }
}

onMounted(load);

function fillPassword() {
  password.value = generatePassword();
}

async function copyPassword() {
  if (!password.value) return;
  await navigator.clipboard.writeText(password.value);
  toast.success("Password copied");
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
    toast.success("Picture updated");
  } catch (err) {
    toast.error(err instanceof Error ? err.message : "Failed to upload avatar");
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
    toast.success("Changes saved");
  } catch (err) {
    error.value = err instanceof Error ? err.message : "Failed to save changes";
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
    toast.success(`${user.value?.username ?? "User"} deleted`);
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
  <div class="mx-auto max-w-2xl" :class="{ 'pb-24': dirty }">
    <RouterLink :to="{ name: 'users' }" class="btn btn-ghost btn-sm -ml-3">
      <Icon name="arrowLeft" :size="14" />
      Users
    </RouterLink>

    <div v-if="loadError" class="card mt-4 flex flex-col items-center px-6 py-14 text-center">
      <div class="flex size-12 items-center justify-center rounded-full bg-fg/6 text-muted">
        <Icon name="user" :size="20" />
      </div>
      <h1 class="m-0 mt-4 text-title">This user couldn't be loaded</h1>
      <p class="m-0 mt-1 text-meta text-muted">{{ loadError }}</p>
    </div>

    <div v-else-if="!user" class="mt-4 flex items-center gap-4" aria-busy="true">
      <span class="size-18 animate-pulse rounded-full bg-fg/8" />
      <span class="flex flex-col gap-2.5">
        <span class="h-5 w-40 animate-pulse rounded-full bg-fg/8" />
        <span class="h-3 w-56 animate-pulse rounded-full bg-fg/5" />
      </span>
    </div>

    <template v-else>
      <header class="mt-3 mb-6 flex items-center gap-4">
        <button
          type="button"
          class="group relative shrink-0 cursor-pointer rounded-full"
          aria-label="Change profile picture"
          @click="triggerAvatarUpload"
        >
          <UserAvatar :key="avatarVersion" :user-id="user.id" :name="user.username" :size="72" />
          <span
            class="absolute -right-0.5 -bottom-0.5 flex size-7 items-center justify-center rounded-full border-[3px] border-canvas bg-primary text-primary-contrast transition-transform group-hover:scale-110"
          >
            <Icon name="camera" :size="13" />
          </span>
        </button>
        <input ref="avatarInput" type="file" accept="image/*" class="hidden" @change="onAvatarSelected" />
        <div class="min-w-0">
          <h1 class="m-0 truncate text-display">{{ user.username }}</h1>
          <div class="mt-1.5 flex flex-wrap items-center gap-2">
            <span v-if="user.role === 'admin'" class="chip bg-accent/12 text-accent">
              <Icon name="shieldCheck" :size="13" />
              Admin
            </span>
            <span v-else class="chip bg-fg/6 text-muted">Member</span>
            <StatusPill :active="user.active" />
            <span v-if="isSelf" class="chip bg-fg/6 text-muted">You</span>
          </div>
        </div>
      </header>

      <form class="flex flex-col gap-5" novalidate @submit.prevent="save">
        <section class="card flex flex-col gap-5 p-5 sm:p-6" aria-labelledby="identity-heading">
          <h2 id="identity-heading" class="eyebrow m-0">Account</h2>

          <div class="field">
            <label for="edit-username">Username</label>
            <input id="edit-username" v-model="username" class="input" autocapitalize="none" spellcheck="false" />
          </div>

          <div class="field">
            <span class="field-label">Role</span>
            <SegmentedControl v-model="role" :options="roleOptions" label="Role" class="w-full sm:w-64" />
            <p class="field-hint">
              {{ role === "admin" ? "Can open this console and manage every account." : "Can sign in to the apps they have access to." }}
            </p>
          </div>

          <div class="field">
            <label for="edit-password">New password</label>
            <div class="flex gap-2">
              <PasswordInput
                id="edit-password"
                v-model="password"
                class="input font-mono placeholder:font-sans"
                placeholder="Unchanged"
                autocomplete="new-password"
              />
              <button type="button" class="btn btn-secondary h-11 px-3.5" title="Generate a password" @click="fillPassword">
                <Icon name="dice" :size="16" />
                <span class="hidden sm:inline">Generate</span>
              </button>
              <button
                type="button"
                class="btn btn-secondary h-11 w-11 px-0"
                title="Copy password"
                aria-label="Copy password"
                :disabled="!password"
                @click="copyPassword"
              >
                <Icon name="copy" :size="16" />
              </button>
            </div>
          </div>

          <div class="flex items-center justify-between gap-3 border-t border-line pt-4">
            <span class="field-label shrink-0">User ID</span>
            <span class="truncate font-mono text-xs text-subtle select-all">{{ user.id }}</span>
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
          <OptionRow
            icon="user"
            title="Active"
            :description="active ? 'This account can sign in.' : 'Disabled: this account can\'t sign in anywhere.'"
          >
            <ToggleSwitch v-model="active" aria-label="Active" />
          </OptionRow>
        </section>

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
        :title="`Delete ${user.username}?`"
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

<style scoped>
.savebar-enter-active {
  transition:
    opacity 200ms var(--ease-out-quart),
    transform 380ms var(--ease-out-expo);
}

.savebar-leave-active {
  transition:
    opacity 140ms var(--ease-in-quart),
    transform 140ms var(--ease-in-quart);
}

.savebar-enter-from,
.savebar-leave-to {
  opacity: 0;
  transform: translateY(1rem);
}
</style>
