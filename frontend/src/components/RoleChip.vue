<script setup lang="ts">
import { ROLE_LABELS, type Role } from "../constants";
import Icon from "./Icon.vue";

withDefaults(defineProps<{ role: Role; compact?: boolean }>(), { compact: false });
</script>

<template>
  <span
    v-if="role === 'admin'"
    class="chip bg-accent/12 text-accent"
    :class="compact ? 'h-5 px-2 text-[0.6875rem]' : ''"
  >
    <Icon name="shieldCheck" :size="13" />
    {{ ROLE_LABELS.admin }}
  </span>
  <span v-else class="chip bg-fg/6 text-muted" :class="compact ? 'h-5 px-2 text-[0.6875rem]' : ''">
    {{ ROLE_LABELS.user }}
  </span>
</template>
