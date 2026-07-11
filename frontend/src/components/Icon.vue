<script setup lang="ts">
import { Icon as Iconify } from "@iconify/vue";

withDefaults(defineProps<{ name: string; size?: number }>(), { size: 16 });

const icons: Record<string, string> = {
  mail: "lucide:mail",
  lock: "lucide:lock",
  search: "lucide:search",
  bell: "lucide:bell",
  help: "lucide:help-circle",
  users: "lucide:users",
  settings: "lucide:settings",
  pencil: "lucide:pencil",
  history: "lucide:history",
  user: "lucide:user",
  camera: "lucide:camera",
  key: "lucide:key",
  calendar: "lucide:calendar",
  chart: "lucide:bar-chart-3",
  plus: "lucide:plus",
  chevronDown: "lucide:chevron-down",
  shield: "lucide:shield",
  briefcase: "lucide:briefcase",
  arrowRight: "lucide:arrow-right",
  logout: "lucide:log-out",
  menu: "lucide:menu",
  x: "lucide:x",
  eye: "lucide:eye",
  eyeOff: "lucide:eye-off",
};
</script>

<template>
  <Iconify :icon="icons[name] ?? name" :width="size" :height="size" />
</template>
