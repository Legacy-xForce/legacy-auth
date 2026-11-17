<script setup lang="ts">
import { ROLE_OPTIONS, type Role } from "../constants";
import SegmentedControl from "./SegmentedControl.vue";

/** Username / display name / role fields, identical on the create and edit screens. */
defineProps<{ idPrefix: string; headingId: string }>();

const username = defineModel<string>("username", { required: true });
const displayName = defineModel<string>("displayName", { required: true });
const role = defineModel<Role>("role", { required: true });
</script>

<template>
  <section class="card flex flex-col gap-5 p-5 sm:p-6" :aria-labelledby="headingId">
    <h2 :id="headingId" class="eyebrow m-0">Account</h2>

    <div class="field">
      <label :for="`${idPrefix}-username`">Username</label>
      <input
        :id="`${idPrefix}-username`"
        v-model="username"
        class="input"
        autocomplete="off"
        autocapitalize="none"
        spellcheck="false"
        data-form-type="other"
        data-lpignore="true"
        data-1p-ignore
        data-bwignore="true"
      />
      <p class="field-hint">Stored lowercase; it is the name they sign in with.</p>
    </div>

    <div class="field">
      <label :for="`${idPrefix}-display-name`">Display name</label>
      <input
        :id="`${idPrefix}-display-name`"
        v-model="displayName"
        class="input"
        autocomplete="off"
        spellcheck="false"
        placeholder="Defaults to the username as typed"
      />
      <p class="field-hint">Shown in the apps and in this console.</p>
    </div>

    <div class="field">
      <span class="field-label">Role</span>
      <SegmentedControl v-model="role" :options="ROLE_OPTIONS" label="Role" class="w-full sm:w-64" />
      <p class="field-hint">
        {{ role === "admin" ? "Can open this console and manage every account." : "Can sign in to the apps they have access to." }}
      </p>
    </div>

    <slot />
  </section>
</template>
