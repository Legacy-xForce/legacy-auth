<script setup lang="ts">
import type { Component } from "vue";
import {
  ArrowLeft,
  ArrowRight,
  AtSign,
  CalendarDays,
  Camera,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Copy,
  Dices,
  Eye,
  EyeOff,
  Fingerprint,
  LoaderCircle,
  Lock,
  LogOut,
  MapPin,
  Palette,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  User,
  UserPlus,
  Users,
  X,
} from "lucide-vue-next";

const props = withDefaults(defineProps<{ name: string; size?: number }>(), { size: 16 });

// Bundled with the app, so icons render on the first paint without a network request.
const icons: Record<string, Component> = {
  alertCircle: CircleAlert,
  alertTriangle: TriangleAlert,
  arrowLeft: ArrowLeft,
  arrowRight: ArrowRight,
  at: AtSign,
  calendar: CalendarDays,
  camera: Camera,
  check: Check,
  checkCircle: CircleCheck,
  chevronLeft: ChevronLeft,
  chevronRight: ChevronRight,
  copy: Copy,
  dice: Dices,
  eye: Eye,
  eyeOff: EyeOff,
  fingerprint: Fingerprint,
  loader: LoaderCircle,
  lock: Lock,
  logout: LogOut,
  mapPin: MapPin,
  palette: Palette,
  plus: Plus,
  search: Search,
  settings: Settings,
  shieldCheck: ShieldCheck,
  trash: Trash2,
  user: User,
  userPlus: UserPlus,
  users: Users,
  x: X,
};

if (import.meta.env.DEV && !icons[props.name]) console.warn(`Unknown icon "${props.name}"`);
</script>

<template>
  <component :is="icons[name] ?? CircleAlert" :size="size" :class="{ 'animate-spin': name === 'loader' }" aria-hidden="true" />
</template>
