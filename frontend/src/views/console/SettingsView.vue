<script setup lang="ts">
import { computed, ref, onMounted } from "vue";
import { api } from "../../api/client";
import { useAuthStore } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { isPasskeySupported } from "../../services/webauthn";
import ConfirmDialog from "../../components/ConfirmDialog.vue";
import FormAlert from "../../components/FormAlert.vue";
import Icon from "../../components/Icon.vue";
import Modal from "../../components/Modal.vue";
import PasswordInput from "../../components/PasswordInput.vue";
import ThemePicker from "../../components/ThemePicker.vue";
import UserAvatar from "../../components/UserAvatar.vue";

const auth = useAuthStore();
const toast = useToastStore();

const username = ref(auth.user?.username ?? "");
const displayName = ref(auth.user?.display_name ?? "");
const profileSaving = ref(false);
const profileError = ref("");
const profileChanged = computed(
  () =>
    (Boolean(username.value.trim()) && username.value.trim().toLowerCase() !== auth.user?.username) ||
    (Boolean(displayName.value.trim()) && displayName.value.trim() !== auth.user?.display_name)
);

const currentPassword = ref("");
const newPassword = ref("");
const passwordSaving = ref(false);
const passwordError = ref("");

const avatarInput = ref<HTMLInputElement | null>(null);
const avatarVersion = ref(0);
const avatarError = ref("");

const passkeySupported = isPasskeySupported();
const passkeys = ref<Array<{ id: string; deviceName: string; createdAt: string }>>([]);
const passkeysLoaded = ref(false);
const passkeyLoading = ref(false);
const passkeyError = ref("");
const passkeyToDelete = ref<string | null>(null);
const naming = ref(false);
const passkeyName = ref("");

onMounted(async () => {
  if (passkeySupported) {
    try {
      passkeys.value = await api.getPasskeys();
    } catch {
      // ignore on mount
    } finally {
      passkeysLoaded.value = true;
    }
  }
});

async function saveProfile() {
  profileError.value = "";
  profileSaving.value = true;
  try {
    await api.patch("/auth/me", {
      username: username.value.trim(),
      display_name: displayName.value.trim(),
    });
    await auth.fetchMe();
    username.value = auth.user?.username ?? "";
    displayName.value = auth.user?.display_name ?? "";
    toast.success("Profile updated");
  } catch (err) {
    profileError.value = err instanceof Error ? err.message : "Failed to update profile";
  } finally {
    profileSaving.value = false;
  }
}

async function changePassword() {
  passwordError.value = "";
  if (!currentPassword.value || !newPassword.value) {
    passwordError.value = "Enter your current password and a new one.";
    return;
  }
  passwordSaving.value = true;
  try {
    await api.post("/auth/change-password", {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
    toast.success("Password changed. Other devices will need to sign in again.");
    currentPassword.value = "";
    newPassword.value = "";
  } catch (err) {
    passwordError.value = err instanceof Error ? err.message : "Failed to change password";
  } finally {
    passwordSaving.value = false;
  }
}

function triggerAvatarUpload() {
  avatarInput.value?.click();
}

async function onAvatarSelected(event: Event) {
  avatarError.value = "";
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);
  try {
    await api.postForm("/auth/profile-picture", formData);
    avatarVersion.value++;
    toast.success("Picture updated");
  } catch (err) {
    avatarError.value = err instanceof Error ? err.message : "Failed to upload avatar";
  } finally {
    (event.target as HTMLInputElement).value = "";
  }
}

/** A name for the new passkey from this browser, e.g. "Chrome on macOS"; the user can change it. */
function guessDeviceName() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return [browser, os].filter(Boolean).join(" on ") || "My device";
}

function startRegisterPasskey() {
  passkeyError.value = "";
  passkeyName.value = guessDeviceName();
  naming.value = true;
}

async function handleRegisterPasskey() {
  naming.value = false;
  passkeyError.value = "";
  passkeyLoading.value = true;
  try {
    await auth.registerPasskey(passkeyName.value.trim() || undefined);
    passkeys.value = await api.getPasskeys();
    toast.success("Passkey added");
  } catch (err: any) {
    if (err?.name === "NotAllowedError") {
      passkeyError.value = "Passkey registration was cancelled.";
    } else {
      passkeyError.value = err instanceof Error ? err.message : "Failed to register passkey";
    }
  } finally {
    passkeyLoading.value = false;
  }
}

function confirmDeletePasskey(id: string) {
  passkeyToDelete.value = id;
}

async function executeDeletePasskey() {
  if (!passkeyToDelete.value) return;
  passkeyError.value = "";
  passkeyLoading.value = true;
  try {
    await api.deletePasskey(passkeyToDelete.value);
    passkeys.value = passkeys.value.filter((p) => p.id !== passkeyToDelete.value);
    toast.success("Passkey removed");
  } catch (err) {
    passkeyError.value = err instanceof Error ? err.message : "Could not remove passkey";
  } finally {
    passkeyLoading.value = false;
    passkeyToDelete.value = null;
  }
}

function formatDate(value: string) {
  return new Date(value).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}
</script>

<template>
  <div class="mx-auto flex max-w-2xl flex-col gap-9">
    <header class="flex items-center gap-4">
      <button
        type="button"
        class="group relative shrink-0 cursor-pointer rounded-full"
        aria-label="Change profile picture"
        @click="triggerAvatarUpload"
      >
        <UserAvatar v-if="auth.user" :key="avatarVersion" :user-id="auth.user.id" :name="auth.user.display_name || auth.user.username" :size="72" />
        <span
          class="absolute -right-0.5 -bottom-0.5 flex size-7 items-center justify-center rounded-full border-[3px] border-canvas bg-primary text-primary-contrast transition-transform group-hover:scale-110"
        >
          <Icon name="camera" :size="13" />
        </span>
      </button>
      <input ref="avatarInput" type="file" accept="image/*" class="hidden" @change="onAvatarSelected" />
      <div class="min-w-0">
        <h1 class="m-0 truncate text-display">{{ auth.user?.display_name || auth.user?.username }}</h1>
        <p class="m-0 mt-0.5 text-meta text-muted">@{{ auth.user?.username }} · {{ auth.isAdmin ? "Administrator" : "Member" }} · Legacy account</p>
      </div>
    </header>

    <FormAlert v-if="avatarError" class="-mt-5">{{ avatarError }}</FormAlert>

    <section class="flex flex-col gap-3" aria-labelledby="appearance-heading">
      <div>
        <h2 id="appearance-heading" class="eyebrow m-0">Appearance</h2>
        <p class="m-0 mt-1 text-meta text-subtle">OLED, Catppuccin or adaptive. Saved on this device only.</p>
      </div>
      <ThemePicker />
    </section>

    <section class="flex flex-col gap-3" aria-labelledby="profile-heading">
      <h2 id="profile-heading" class="eyebrow m-0">Profile</h2>
      <form class="card flex flex-col gap-4 p-5 sm:p-6" novalidate @submit.prevent="saveProfile">
        <div class="field">
          <label for="settings-display-name">Display name</label>
          <input id="settings-display-name" v-model="displayName" class="input" autocomplete="name" spellcheck="false" />
          <p class="field-hint">How your name appears in the Legacy apps.</p>
        </div>
        <div class="field">
          <label for="settings-username">Username</label>
          <input id="settings-username" v-model="username" class="input min-w-0 flex-1" autocomplete="username" autocapitalize="none" spellcheck="false" />
          <p class="field-hint">Stored lowercase. You sign in to every Legacy app with this name.</p>
        </div>
        <FormAlert v-if="profileError">{{ profileError }}</FormAlert>
        <div class="flex justify-end">
          <button type="submit" class="btn btn-primary h-11 shrink-0" :disabled="profileSaving || !profileChanged">
            <Icon v-if="profileSaving" name="loader" :size="16" />
            {{ profileSaving ? "Saving…" : "Save" }}
          </button>
        </div>
      </form>
    </section>

    <section class="flex flex-col gap-3" aria-labelledby="password-heading">
      <h2 id="password-heading" class="eyebrow m-0">Password</h2>
      <form class="card flex flex-col gap-4 p-5 sm:p-6" novalidate @submit.prevent="changePassword">
        <!-- Lets password managers pair the new password with this account. -->
        <input type="text" class="hidden" autocomplete="username" :value="auth.user?.username" readonly tabindex="-1" aria-hidden="true" />
        <div class="field">
          <label for="current-password">Current password</label>
          <PasswordInput id="current-password" v-model="currentPassword" class="input" autocomplete="current-password" />
        </div>
        <div class="field">
          <label for="new-password">New password</label>
          <PasswordInput id="new-password" v-model="newPassword" class="input" autocomplete="new-password" />
          <p class="field-hint">Other devices will need to sign in again.</p>
        </div>
        <FormAlert v-if="passwordError">{{ passwordError }}</FormAlert>
        <div class="flex justify-end">
          <button type="submit" class="btn btn-primary" :disabled="passwordSaving">
            <Icon v-if="passwordSaving" name="loader" :size="16" />
            {{ passwordSaving ? "Updating…" : "Update password" }}
          </button>
        </div>
      </form>
    </section>

    <section v-if="passkeySupported" class="flex flex-col gap-3" aria-labelledby="passkeys-heading">
      <div class="flex items-end justify-between gap-4">
        <div>
          <h2 id="passkeys-heading" class="eyebrow m-0">Passkeys</h2>
          <p class="m-0 mt-1 text-meta text-subtle">Sign in with Touch ID, Face ID, Windows Hello or a security key.</p>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="passkeyLoading" @click="startRegisterPasskey">
          <Icon :name="passkeyLoading ? 'loader' : 'plus'" :size="14" />
          Add passkey
        </button>
      </div>

      <div class="card overflow-hidden">
        <ul v-if="passkeys.length" class="m-0 list-none divide-y divide-line p-0">
          <li v-for="pk in passkeys" :key="pk.id" class="flex items-center gap-3.5 px-5 py-3.5 sm:px-6">
            <div class="flex size-10 shrink-0 items-center justify-center rounded-ui bg-accent/12 text-accent">
              <Icon name="fingerprint" :size="18" />
            </div>
            <div class="min-w-0 flex-1">
              <div class="truncate text-body font-semibold">{{ pk.deviceName || "Passkey" }}</div>
              <div class="text-meta text-muted">Added {{ formatDate(pk.createdAt) }}</div>
            </div>
            <button
              type="button"
              class="icon-btn hover:not-disabled:bg-danger/12 hover:not-disabled:text-danger"
              :disabled="passkeyLoading"
              :aria-label="`Remove ${pk.deviceName || 'passkey'}`"
              @click="confirmDeletePasskey(pk.id)"
            >
              <Icon name="trash" :size="16" />
            </button>
          </li>
        </ul>
        <div v-else-if="passkeysLoaded" class="flex flex-col items-center px-6 py-10 text-center">
          <div class="flex size-12 items-center justify-center rounded-full bg-fg/6 text-muted">
            <Icon name="fingerprint" :size="22" />
          </div>
          <p class="m-0 mt-3 text-body font-semibold">No passkeys yet</p>
          <p class="m-0 mt-0.5 max-w-xs text-meta text-muted">Add one to sign in without typing your password.</p>
        </div>
        <div v-else class="flex items-center gap-3.5 px-5 py-3.5 sm:px-6" aria-busy="true">
          <span class="size-10 animate-pulse rounded-ui bg-fg/8" />
          <span class="h-3 w-32 animate-pulse rounded-full bg-fg/8" />
        </div>
      </div>

      <FormAlert v-if="passkeyError">{{ passkeyError }}</FormAlert>

      <Modal :open="naming" labelledby="passkey-name-title" @close="naming = false">
        <form novalidate @submit.prevent="handleRegisterPasskey">
          <div class="mb-4 flex size-11 items-center justify-center rounded-full bg-accent/12 text-accent">
            <Icon name="fingerprint" :size="20" />
          </div>
          <h2 id="passkey-name-title" class="m-0 text-headline">Name this passkey</h2>
          <p class="m-0 mt-2 text-body text-muted">So you can tell it apart from your other devices later.</p>
          <input
            v-model="passkeyName"
            class="input mt-5"
            aria-label="Passkey name"
            maxlength="64"
            autocomplete="off"
            autofocus
          />
          <div class="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <button type="button" class="btn btn-secondary" @click="naming = false">Cancel</button>
            <button type="submit" class="btn btn-primary">Continue</button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        :open="Boolean(passkeyToDelete)"
        title="Remove this passkey?"
        message="You won't be able to sign in with it any more. You can add it again later."
        confirm-label="Remove"
        danger
        :busy="passkeyLoading"
        @confirm="executeDeletePasskey"
        @cancel="passkeyToDelete = null"
      />
    </section>
  </div>
</template>
