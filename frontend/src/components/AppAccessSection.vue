<script setup lang="ts">
import { APP_SCOPES, type AppScopeKey } from "../constants";
import OptionRow from "./OptionRow.vue";
import ToggleSwitch from "./ToggleSwitch.vue";

/** The per-app scopes + active flag, identical on the create and edit screens. */
withDefaults(defineProps<{ headingId?: string; activeDescription?: string }>(), {
  headingId: "access-heading",
  activeDescription: "Disabled accounts can't sign in anywhere.",
});

const calendar = defineModel<boolean>("calendar", { required: true });
const tracker = defineModel<boolean>("tracker", { required: true });
const active = defineModel<boolean>("active", { required: true });

const scopeValue = (key: AppScopeKey) => (key === "calendar" ? calendar.value : tracker.value);
function setScope(key: AppScopeKey, value: boolean) {
  if (key === "calendar") calendar.value = value;
  else tracker.value = value;
}
</script>

<template>
  <section class="card divide-y divide-line overflow-hidden" :aria-labelledby="headingId">
    <h2 :id="headingId" class="eyebrow m-0 px-5 pt-5 pb-1 sm:px-6">App access</h2>
    <OptionRow
      v-for="(scope, index) in APP_SCOPES"
      :key="scope.key"
      :icon="scope.icon"
      :title="scope.label"
      :description="scope.description"
      :class="index === 0 ? 'border-t-0!' : ''"
    >
      <ToggleSwitch
        :model-value="scopeValue(scope.key)"
        :aria-label="`${scope.label} access`"
        @update:model-value="setScope(scope.key, $event)"
      />
    </OptionRow>
    <OptionRow icon="user" title="Active" :description="activeDescription">
      <ToggleSwitch v-model="active" aria-label="Active" />
    </OptionRow>
  </section>
</template>
