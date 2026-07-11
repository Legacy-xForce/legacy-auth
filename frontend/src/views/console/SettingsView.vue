<script setup lang="ts">
import { ref } from "vue";
import { api } from "../../api/client";
import { useAuthStore } from "../../stores/auth";
import Icon from "../../components/Icon.vue";
import UserAvatar from "../../components/UserAvatar.vue";
import PasswordInput from "../../components/PasswordInput.vue";

const auth = useAuthStore();

const username = ref(auth.user?.username ?? "");
const usernameSaving = ref(false);
const usernameMessage = ref("");
const usernameError = ref("");

const currentPassword = ref("");
const newPassword = ref("");
const passwordSaving = ref(false);
const passwordMessage = ref("");
const passwordError = ref("");

const avatarInput = ref<HTMLInputElement | null>(null);
const avatarVersion = ref(0);
const avatarError = ref("");

async function saveUsername() {
  usernameError.value = "";
  usernameMessage.value = "";
  usernameSaving.value = true;
  try {
    await api.patch("/auth/me", { username: username.value.trim() });
    await auth.fetchMe();
    usernameMessage.value = "Username updated.";
  } catch (err) {
    usernameError.value = err instanceof Error ? err.message : "Failed to update username";
  } finally {
    usernameSaving.value = false;
  }
}

async function changePassword() {
  passwordError.value = "";
  passwordMessage.value = "";
  if (!currentPassword.value || !newPassword.value) {
    passwordError.value = "Both current and new password are required.";
    return;
  }
  passwordSaving.value = true;
  try {
    await api.post("/auth/change-password", {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    });
    passwordMessage.value = "Password changed. You'll need to sign in again on other devices.";
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
  } catch (err) {
    avatarError.value = err instanceof Error ? err.message : "Failed to upload avatar";
  } finally {
    (event.target as HTMLInputElement).value = "";
  }
}
</script>

<template>
  <div class="flex max-w-140 flex-col gap-5">
    <div>
      <h1 class="m-0 mb-1 text-2xl font-bold">Settings</h1>
      <p class="m-0 mb-2 text-sm text-text-muted">Manage your own profile and security credentials.</p>
    </div>

    <div class="card p-6">
      <h3 class="m-0 mb-4 text-base">Profile Picture</h3>
      <div class="flex items-center gap-5">
        <UserAvatar v-if="auth.user" :key="avatarVersion" :user-id="auth.user.id" :size="72" />
        <div>
          <button class="btn btn-ghost" @click="triggerAvatarUpload">
            <Icon name="camera" :size="15" />
            Update Avatar
          </button>
          <p v-if="avatarError" class="mt-2.5 text-[0.82rem] text-danger">{{ avatarError }}</p>
        </div>
        <input ref="avatarInput" type="file" accept="image/*" class="hidden" @change="onAvatarSelected" />
      </div>
    </div>

    <div class="card p-6">
      <h3 class="m-0 mb-4 text-base">Change Username</h3>
      <div class="field mb-4">
        <label>Username</label>
        <input v-model="username" class="input" />
      </div>
      <button class="btn btn-primary" :disabled="usernameSaving" @click="saveUsername">
        {{ usernameSaving ? "Saving…" : "Save Username" }}
      </button>
      <p v-if="usernameMessage" class="mt-2.5 text-[0.82rem] text-success">{{ usernameMessage }}</p>
      <p v-if="usernameError" class="mt-2.5 text-[0.82rem] text-danger">{{ usernameError }}</p>
    </div>

    <div class="card p-6">
      <h3 class="m-0 mb-4 text-base">Reset Password</h3>
      <div class="field mb-4">
        <label>Current Password</label>
        <PasswordInput v-model="currentPassword" class="input" autocomplete="current-password" />
      </div>
      <div class="field mb-4">
        <label>New Password</label>
        <PasswordInput v-model="newPassword" class="input" autocomplete="new-password" />
      </div>
      <button class="btn btn-primary" :disabled="passwordSaving" @click="changePassword">
        {{ passwordSaving ? "Updating…" : "Update Password" }}
      </button>
      <p v-if="passwordMessage" class="mt-2.5 text-[0.82rem] text-success">{{ passwordMessage }}</p>
      <p v-if="passwordError" class="mt-2.5 text-[0.82rem] text-danger">{{ passwordError }}</p>
    </div>
  </div>
</template>
